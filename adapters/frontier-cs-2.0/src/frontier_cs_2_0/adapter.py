from __future__ import annotations

import json
import logging
import os
import re
import shutil
import secrets
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from harbor.models.task.paths import TaskPaths

from .utils import (
    FrontierCS20Problem,
    load_problem_config,
    normalize_task_id,
    read_problem_statement,
)

LOGGER = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "task-template"
MAX_PUBLIC_ASSET_BYTES = 64 * 1024 * 1024
SAFE_PACKAGE_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
SAFE_PACKAGE_VERSION = r"[A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?"
SAFE_PIN_PATTERN = re.compile(
    rf"{SAFE_PACKAGE_NAME}=={SAFE_PACKAGE_VERSION}\Z"
)
SAFE_JUDGE_PACKAGE_PATTERN = re.compile(
    rf"{SAFE_PACKAGE_NAME}(?:=={SAFE_PACKAGE_VERSION})?\Z"
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_SOURCE_DIRECTORY_FLAGS = os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC
_SOURCE_FILE_FLAGS = os.O_RDONLY | _NOFOLLOW | _CLOEXEC
_DESTINATION_DIRECTORY_FLAGS = os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC
_DESTINATION_FILE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
)
PublicSnapshotManifest = dict[tuple[str, ...], os.stat_result]


def _public_assets_opted_in(harbor_app_dir: Path) -> bool:
    """Recognize a public directory or symlink as an explicit opt-in."""
    try:
        mode = (harbor_app_dir / "public").lstat().st_mode
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(mode) or stat.S_ISLNK(mode)


def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _same_snapshot_metadata(
    first: os.stat_result,
    second: os.stat_result,
) -> bool:
    return (
        _same_inode(first, second)
        and stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def _fstat_or_close(descriptor: int) -> os.stat_result:
    """Take ownership only after the first fstat succeeds."""
    try:
        return os.fstat(descriptor)
    except Exception:
        os.close(descriptor)
        raise


def _open_public_source_entry(name: str, flags: int, *, dir_fd: int) -> int:
    """Open one source entry relative to its already-pinned parent directory."""
    return os.open(name, flags, dir_fd=dir_fd)


def _open_pinned_source_directory(
    name: str,
    *,
    parent_fd: int,
    label: str,
    expected: os.stat_result | None = None,
) -> int:
    """Open and identity-check a source directory without following links."""
    before = expected
    if before is None:
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(
                f"public assets source path component {label} changed during snapshot"
            ) from exc

    if stat.S_ISLNK(before.st_mode):
        raise ValueError(
            f"public assets source path component {label} may not be a symlink"
        )
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError(
            f"public assets source path component {label} must be a directory"
        )

    try:
        descriptor = _open_public_source_entry(
            name,
            _SOURCE_DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise ValueError(
            f"public assets source path component {label} may not be a symlink "
            "and must not change during snapshot"
        ) from exc

    opened = _fstat_or_close(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or not _same_snapshot_metadata(
        before,
        opened,
    ):
        os.close(descriptor)
        raise ValueError(
            f"public assets source path component {label} changed during snapshot"
        )
    return descriptor


def _open_public_source_root(harbor_app_dir: Path) -> int:
    """Pin harbor/app/public by traversing from the problem directory."""
    problem_dir = harbor_app_dir.parent.parent
    try:
        problem_before = problem_dir.lstat()
    except OSError as exc:
        raise ValueError("public assets problem directory is unavailable") from exc

    if stat.S_ISLNK(problem_before.st_mode) or not stat.S_ISDIR(
        problem_before.st_mode
    ):
        raise ValueError(
            "public assets source path problem directory must be a real directory"
        )

    try:
        problem_fd = os.open(problem_dir, _SOURCE_DIRECTORY_FLAGS)
    except OSError as exc:
        raise ValueError(
            "public assets source path problem directory may not be a symlink"
        ) from exc
    problem_opened = _fstat_or_close(problem_fd)
    if not _same_snapshot_metadata(problem_before, problem_opened):
        os.close(problem_fd)
        raise ValueError("public assets problem directory changed during snapshot")

    descriptors = [problem_fd]
    try:
        harbor_fd = _open_pinned_source_directory(
            "harbor", parent_fd=problem_fd, label="harbor"
        )
        descriptors.append(harbor_fd)
        app_fd = _open_pinned_source_directory(
            "app", parent_fd=harbor_fd, label="harbor/app"
        )
        descriptors.append(app_fd)
        public_fd = _open_pinned_source_directory(
            "public", parent_fd=app_fd, label="harbor/app/public"
        )
        descriptors.append(public_fd)
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise

    for descriptor in descriptors[:-1]:
        os.close(descriptor)
    return public_fd


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short write while staging public assets")
        remaining = remaining[written:]


def _read_public_source_chunk(descriptor: int, size: int) -> bytes:
    return os.read(descriptor, size)


def _open_created_public_destination_directory(
    name: str,
    *,
    parent_fd: int,
    expected: os.stat_result,
) -> int:
    """Pin a just-created destination directory across lstat/open/fstat."""
    try:
        descriptor = os.open(
            name,
            _DESTINATION_DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise ValueError("public assets destination changed during snapshot") from exc
    opened = _fstat_or_close(descriptor)
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        os.close(descriptor)
        raise ValueError("public assets destination changed during snapshot") from exc
    if (
        not stat.S_ISDIR(current.st_mode)
        or not _same_inode(expected, current)
        or not _same_inode(current, opened)
    ):
        os.close(descriptor)
        raise ValueError("public assets destination changed during snapshot")
    return descriptor


def _snapshot_public_directory(
    source_fd: int,
    destination_fd: int,
    *,
    relative: Path,
    total_bytes: list[int],
    manifest: PublicSnapshotManifest,
) -> None:
    """Copy a pinned public directory into a private descriptor-relative tree."""
    directory_before = os.fstat(source_fd)
    try:
        names = sorted(os.listdir(source_fd))
    except OSError as exc:
        raise ValueError("public assets changed during snapshot") from exc

    source_entries: dict[str, os.stat_result] = {}
    for name in names:
        child_relative = relative / name
        manifest_path = child_relative.parts
        try:
            before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(
                f"public asset changed during snapshot: {child_relative}"
            ) from exc
        source_entries[name] = before

        if stat.S_ISLNK(before.st_mode):
            raise ValueError(
                f"public assets may not contain symlinks: {child_relative}"
            )

        if stat.S_ISDIR(before.st_mode):
            child_source_fd = _open_pinned_source_directory(
                name,
                parent_fd=source_fd,
                label=str(child_relative),
                expected=before,
            )
            try:
                os.mkdir(name, mode=0o700, dir_fd=destination_fd)
                try:
                    child_created = os.stat(
                        name,
                        dir_fd=destination_fd,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise ValueError(
                        "public assets destination changed during snapshot"
                    ) from exc
                child_destination_fd = (
                    _open_created_public_destination_directory(
                        name,
                        parent_fd=destination_fd,
                        expected=child_created,
                    )
                )
                manifest[manifest_path] = child_created
                try:
                    _snapshot_public_directory(
                        child_source_fd,
                        child_destination_fd,
                        relative=child_relative,
                        total_bytes=total_bytes,
                        manifest=manifest,
                    )
                    os.fchmod(
                        child_destination_fd,
                        stat.S_IMODE(os.fstat(child_source_fd).st_mode),
                    )
                    manifest[manifest_path] = os.fstat(child_destination_fd)
                finally:
                    os.close(child_destination_fd)
            finally:
                os.close(child_source_fd)
            continue

        if not stat.S_ISREG(before.st_mode):
            raise ValueError(
                "public assets may contain only directories and regular files: "
                f"{child_relative}"
            )

        try:
            child_source_fd = _open_public_source_entry(
                name,
                _SOURCE_FILE_FLAGS,
                dir_fd=source_fd,
            )
        except OSError as exc:
            raise ValueError(
                f"public assets may not contain symlinks: {child_relative}"
            ) from exc
        try:
            opened = os.fstat(child_source_fd)
            if not stat.S_ISREG(opened.st_mode) or not _same_snapshot_metadata(
                before,
                opened,
            ):
                raise ValueError(
                    f"public asset changed during snapshot: {child_relative}"
                )
            child_destination_fd = os.open(
                name,
                _DESTINATION_FILE_FLAGS,
                stat.S_IMODE(opened.st_mode),
                dir_fd=destination_fd,
            )
            try:
                destination_opened = os.fstat(child_destination_fd)
                destination_entry = os.stat(
                    name,
                    dir_fd=destination_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(destination_entry.st_mode)
                    or not _same_inode(destination_opened, destination_entry)
                ):
                    raise ValueError(
                        "public assets destination changed during snapshot"
                    )
                manifest[manifest_path] = destination_opened
                while True:
                    chunk = _read_public_source_chunk(
                        child_source_fd,
                        1024 * 1024,
                    )
                    if not chunk:
                        break
                    total_bytes[0] += len(chunk)
                    if total_bytes[0] > MAX_PUBLIC_ASSET_BYTES:
                        raise ValueError(
                            "public assets exceed the 64 MiB size limit"
                        )
                    _write_all(child_destination_fd, chunk)
                source_after = os.fstat(child_source_fd)
                if not _same_snapshot_metadata(opened, source_after):
                    raise ValueError(
                        f"public asset changed during snapshot: {child_relative}"
                    )
                os.fchmod(child_destination_fd, stat.S_IMODE(opened.st_mode))
                manifest[manifest_path] = os.fstat(child_destination_fd)
            finally:
                os.close(child_destination_fd)
        finally:
            os.close(child_source_fd)

    try:
        names_after = sorted(os.listdir(source_fd))
    except OSError as exc:
        raise ValueError("public assets changed during snapshot") from exc
    if names_after != names:
        raise ValueError("public assets changed during snapshot")
    for name, before in source_entries.items():
        try:
            after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(
                f"public asset changed during snapshot: {relative / name}"
            ) from exc
        if not _same_snapshot_metadata(before, after):
            raise ValueError(
                f"public asset changed during snapshot: {relative / name}"
            )
    directory_after = os.fstat(source_fd)
    if not _same_snapshot_metadata(directory_before, directory_after):
        raise ValueError("public assets changed during snapshot")


def _open_pinned_public_destination(destination: Path) -> tuple[int, os.stat_result]:
    """Pin the generated harbor_app directory before creating snapshot state."""
    try:
        before = destination.lstat()
    except OSError as exc:
        raise ValueError("public assets destination is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ValueError("public assets destination must be a real directory")
    try:
        descriptor = os.open(destination, _DESTINATION_DIRECTORY_FLAGS)
    except OSError as exc:
        raise ValueError("public assets destination may not be a symlink") from exc
    opened = _fstat_or_close(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or not _same_inode(before, opened):
        os.close(descriptor)
        raise ValueError("public assets destination changed during snapshot")
    return descriptor, opened


def _create_private_public_destination(parent_fd: int) -> tuple[str, int]:
    """Create a private random child directory under a pinned destination."""
    for _ in range(32):
        name = f".public-snapshot-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            created = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            # The new name was already replaced; its identity is unknown, so
            # leave it untouched rather than risk deleting another entry.
            raise ValueError(
                "public assets private destination changed during snapshot"
            )
        try:
            descriptor = _open_created_public_destination_directory(
                name,
                parent_fd=parent_fd,
                expected=created,
            )
        except Exception:
            _remove_public_destination_entry(parent_fd, name, expected=created)
            raise
        return name, descriptor
    raise FileExistsError("could not allocate a private public snapshot directory")


def _destination_entry_matches(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
) -> bool:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return _same_inode(current, expected) and stat.S_IFMT(
        current.st_mode
    ) == stat.S_IFMT(expected.st_mode)


def _manifest_children(
    manifest: PublicSnapshotManifest,
    prefix: tuple[str, ...],
) -> dict[str, os.stat_result]:
    child_length = len(prefix) + 1
    return {
        path[-1]: identity
        for path, identity in manifest.items()
        if len(path) == child_length and path[:-1] == prefix
    }


def _validate_public_snapshot_manifest(
    directory_fd: int,
    manifest: PublicSnapshotManifest,
    *,
    prefix: tuple[str, ...] = (),
) -> None:
    """Validate the exact no-follow destination tree against pinned identities."""
    expected_children = _manifest_children(manifest, prefix)
    try:
        actual_names = set(os.listdir(directory_fd))
    except OSError as exc:
        raise ValueError("public assets snapshot contents changed") from exc
    if actual_names != set(expected_children):
        raise ValueError("public assets snapshot contents changed")

    for name, expected in expected_children.items():
        try:
            current = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ValueError("public assets snapshot contents changed") from exc
        if not _same_snapshot_metadata(current, expected):
            raise ValueError("public assets snapshot contents changed")

        flags = (
            _DESTINATION_DIRECTORY_FLAGS
            if stat.S_ISDIR(expected.st_mode)
            else _SOURCE_FILE_FLAGS
        )
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except OSError as exc:
            raise ValueError("public assets snapshot contents changed") from exc
        try:
            opened = os.fstat(descriptor)
            if not _same_snapshot_metadata(opened, expected):
                raise ValueError("public assets snapshot contents changed")
            if stat.S_ISDIR(expected.st_mode):
                _validate_public_snapshot_manifest(
                    descriptor,
                    manifest,
                    prefix=prefix + (name,),
                )
            elif not stat.S_ISREG(expected.st_mode):
                raise ValueError("public assets snapshot contents changed")
        finally:
            os.close(descriptor)
        try:
            after = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ValueError("public assets snapshot contents changed") from exc
        if not _same_snapshot_metadata(after, expected):
            raise ValueError("public assets snapshot contents changed")

    try:
        names_after = set(os.listdir(directory_fd))
    except OSError as exc:
        raise ValueError("public assets snapshot contents changed") from exc
    if names_after != set(expected_children):
        raise ValueError("public assets snapshot contents changed")


def _remove_public_destination_entry(
    parent_fd: int,
    name: str,
    *,
    expected: os.stat_result,
    manifest: PublicSnapshotManifest | None = None,
    prefix: tuple[str, ...] = (),
) -> bool:
    """Remove only the entry whose identity was pinned by the caller."""
    if not _destination_entry_matches(parent_fd, name, expected):
        return False

    if stat.S_ISDIR(expected.st_mode):
        try:
            descriptor = os.open(
                name,
                _DESTINATION_DIRECTORY_FLAGS,
                dir_fd=parent_fd,
            )
        except OSError:
            return False
        try:
            opened = os.fstat(descriptor)
            if not _same_inode(opened, expected) or not stat.S_ISDIR(
                opened.st_mode
            ):
                return False
            expected_children = (
                _manifest_children(manifest, prefix) if manifest is not None else {}
            )
            try:
                actual_names = set(os.listdir(descriptor))
            except OSError:
                return False
            if actual_names != set(expected_children):
                return False
            for child, child_expected in expected_children.items():
                if not _remove_public_destination_entry(
                    descriptor,
                    child,
                    expected=child_expected,
                    manifest=manifest,
                    prefix=prefix + (child,),
                ):
                    return False
        finally:
            os.close(descriptor)
        if not _destination_entry_matches(parent_fd, name, expected):
            return False
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            return False
        return True

    if not stat.S_ISREG(expected.st_mode):
        return False
    try:
        descriptor = os.open(
            name,
            _SOURCE_FILE_FLAGS,
            dir_fd=parent_fd,
        )
    except OSError:
        return False
    try:
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not _same_inode(opened, expected) or not stat.S_ISREG(opened.st_mode):
        return False
    if not _destination_entry_matches(parent_fd, name, expected):
        return False
    try:
        os.unlink(name, dir_fd=parent_fd)
    except OSError:
        return False
    return True


def _rename_public_snapshot_entry(parent_fd: int, temporary_name: str) -> None:
    os.rename(
        temporary_name,
        "public",
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
    )


def _finalize_public_snapshot(
    parent_fd: int,
    temporary_name: str,
    snapshot_fd: int,
    manifest: PublicSnapshotManifest,
) -> None:
    """Install a snapshot only while its directory entry retains its identity."""
    snapshot_identity = os.fstat(snapshot_fd)
    if not _destination_entry_matches(
        parent_fd,
        temporary_name,
        snapshot_identity,
    ):
        raise ValueError("public assets private destination changed before finalize")

    _validate_public_snapshot_manifest(snapshot_fd, manifest)
    _rename_public_snapshot_entry(parent_fd, temporary_name)

    if not _destination_entry_matches(parent_fd, "public", snapshot_identity):
        raise ValueError("installed public assets changed during finalize")
    _validate_public_snapshot_manifest(snapshot_fd, manifest)


def _snapshot_public_assets(
    harbor_app_dir: Path,
    generated_harbor_app_dir: Path,
) -> None:
    """Create and atomically install a no-follow snapshot of public assets."""
    generated_fd, generated_identity = _open_pinned_public_destination(
        generated_harbor_app_dir
    )
    source_fd = -1
    temporary_name: str | None = None
    destination_fd = -1
    finalized = False
    manifest: PublicSnapshotManifest = {}
    try:
        source_fd = _open_public_source_root(harbor_app_dir)
        temporary_name, destination_fd = _create_private_public_destination(
            generated_fd
        )
        _snapshot_public_directory(
            source_fd,
            destination_fd,
            relative=Path(),
            total_bytes=[0],
            manifest=manifest,
        )

        try:
            current_destination = generated_harbor_app_dir.lstat()
        except OSError as exc:
            raise ValueError("public assets destination changed during snapshot") from exc
        if not _same_inode(generated_identity, current_destination):
            raise ValueError("public assets destination changed during snapshot")

        os.fchmod(destination_fd, stat.S_IMODE(os.fstat(source_fd).st_mode))
        _finalize_public_snapshot(
            generated_fd,
            temporary_name,
            destination_fd,
            manifest,
        )
        finalized = True
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if not finalized and temporary_name is not None and destination_fd >= 0:
            snapshot_identity = os.fstat(destination_fd)
            for candidate in (temporary_name, "public"):
                _remove_public_destination_entry(
                    generated_fd,
                    candidate,
                    expected=snapshot_identity,
                    manifest=manifest,
                )
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(generated_fd)


def _root_app_copy_ignore(
    harbor_app_dir: Path,
    *,
    exclude_input: bool,
    exclude_public: bool,
):
    """Ignore opt-in roots only at harbor/app, never recursively."""
    excluded = {
        name
        for name, enabled in (
            ("input", exclude_input),
            ("public", exclude_public),
        )
        if enabled
    }

    def ignore(directory: str, names: list[str]) -> set[str]:
        if Path(directory) != harbor_app_dir:
            return set()
        return excluded.intersection(names)

    return ignore if excluded else None


def _agent_pip_package_names(
    runtime: dict[str, object], *, problem_id: str
) -> list[str]:
    packages = [str(pkg) for pkg in runtime.get("pip_packages", []) or []]
    for package in packages:
        if SAFE_PIN_PATTERN.fullmatch(package) is None:
            raise ValueError(
                f"{problem_id}: runtime.pip_packages entries must be exact safe "
                f"name==version pins: {package!r}"
            )
    return packages


def _judge_pip_package_names(
    runtime: dict[str, object], *, problem_id: str
) -> list[str]:
    packages = [str(pkg) for pkg in runtime.get("judge_pip_packages", []) or []]
    for package in packages:
        if SAFE_JUDGE_PACKAGE_PATTERN.fullmatch(package) is None:
            raise ValueError(
                f"{problem_id}: runtime.judge_pip_packages entries must be "
                f"shell-safe bare names or exact name==version pins: {package!r}"
            )
    return packages


def _make_task_paths(task_dir: Path):
    try:
        from harbor.models.task.paths import TaskPaths

        return TaskPaths(task_dir=task_dir)
    except ImportError:
        return SimpleNamespace(
            task_dir=task_dir,
            environment_dir=task_dir / "environment",
            solution_dir=task_dir / "solution",
            tests_dir=task_dir / "tests",
            instruction_path=task_dir / "instruction.md",
            config_path=task_dir / "task.toml",
        )


def discover_problems(frontier_cs_root: Path) -> list[FrontierCS20Problem]:
    """Scan the Frontier-CS repo and load metadata for all 2.0 problems."""
    problems_dir = frontier_cs_root / "2.0" / "problems"
    problems: list[FrontierCS20Problem] = []

    if not problems_dir.is_dir():
        raise FileNotFoundError(f"Frontier-CS 2.0 problems not found: {problems_dir}")

    for evaluator_path in sorted(problems_dir.rglob("evaluator.py")):
        problem_dir = evaluator_path.parent
        config_path = problem_dir / "config.yaml"
        config = load_problem_config(config_path) if config_path.exists() else {}
        runtime = config.get("runtime", {}) or {}
        docker = runtime.get("docker", {}) or {}
        rel_id = str(problem_dir.relative_to(problems_dir))

        problems.append(
            FrontierCS20Problem(
                problem_id=rel_id,
                task_id=normalize_task_id(rel_id),
                problem_dir=problem_dir,
                statement=read_problem_statement(problem_dir),
                tag=str(config.get("tag", "optimization")),
                language=str(runtime.get("language", "python")),
                timeout_seconds=int(runtime.get("timeout_seconds", 10800)),
                docker_image=str(docker.get("image", "ubuntu:24.04")),
                judge_docker_image=(
                    str(docker["judge_image"]) if "judge_image" in docker else None
                ),
                config=config,
            )
        )

    return problems


class FrontierCS20Adapter:
    """Generate Harbor tasks for Frontier-CS 2.0 problems."""

    def __init__(
        self,
        frontier_cs_root: Path,
        output_dir: Path,
        *,
        limit: int | None = None,
        overwrite: bool = False,
        task_ids: Iterable[str] | None = None,
        template_dir: Path | None = None,
        docker_image: str | None = None,
    ):
        self.root = Path(frontier_cs_root)
        self.output_dir = Path(output_dir)
        self.limit = limit
        self.overwrite = overwrite
        self.task_ids = set(task_ids) if task_ids is not None else None
        self.template_dir = Path(template_dir or TEMPLATE_DIR)
        self.docker_image = docker_image

    def run(self) -> list[Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        problems = discover_problems(self.root)
        if self.task_ids is not None:
            problems = [p for p in problems if p.problem_id in self.task_ids]
        if self.limit is not None:
            problems = problems[: self.limit]

        results: list[Path] = []
        for problem in problems:
            generated = self.generate_task(problem, overwrite=self.overwrite)
            if generated is not None:
                results.append(generated)
        return results

    def generate_task(
        self, problem: FrontierCS20Problem, *, overwrite: bool = False
    ) -> Path | None:
        task_dir = self.output_dir / problem.task_id
        if task_dir.exists():
            if not overwrite:
                LOGGER.info("Skipping %s (already exists)", task_dir.name)
                return None
            shutil.rmtree(task_dir)

        task_paths = _make_task_paths(task_dir)
        task_paths.task_dir.mkdir(parents=True, exist_ok=True)
        task_paths.environment_dir.mkdir(parents=True, exist_ok=True)
        task_paths.solution_dir.mkdir(parents=True, exist_ok=True)
        task_paths.tests_dir.mkdir(parents=True, exist_ok=True)

        self._write_instruction(task_paths, problem)
        verifier_token = secrets.token_urlsafe(32)
        self._write_environment(task_paths, problem, verifier_token=verifier_token)
        self._write_tests(task_paths, problem, verifier_token=verifier_token)
        self._write_solution(task_paths, problem)
        self._write_task_config(task_paths, problem)
        LOGGER.info("  [OK] %s", problem.problem_id)
        return task_paths.task_dir

    def _write_instruction(self, task_paths: "TaskPaths", problem: FrontierCS20Problem) -> None:
        submission = problem.config.get("submission", {}) or {}
        submission_kind = str(submission.get("kind", "file"))
        submission_path = str(submission.get("path", "/app/solution.py"))
        if submission_kind == "directory":
            workflow = (
                "Create or modify the project under `/app`. You can call "
                "`bash /app/submit.sh` at any time to package a snapshot of `/app` "
                "and enqueue it for the same black-box judge used by the final "
                "verifier. Submissions are asynchronous: use "
                "`bash /app/submissions.sh` and `bash /app/wait_submission.sh <uuid>` "
                "to inspect results. The evaluator implementation and hidden "
                "benchmark data are intentionally not available in the agent "
                "workspace. Read `AGENT.md` for the shared submission workflow. "
                "The task statement defines the required build and runtime contract.\n\n"
                f"Final submission path: `{submission_path}`\n"
            )
        else:
            workflow = (
                f"Create a {problem.language} solution at `{submission_path}`. "
                "You can call `bash /app/submit.sh` at any time to enqueue a "
                "snapshot for the same black-box judge used by the final verifier. "
                "Submissions are asynchronous: use `bash /app/submissions.sh` and "
                "`bash /app/wait_submission.sh <uuid>` to inspect results. The "
                "evaluator implementation is intentionally not available in the "
                "agent workspace. Read `AGENT.md` for the shared submission workflow.\n"
            )

        instruction = (
            "You are solving a Frontier-CS 2.0 open-ended optimization problem.\n\n"
            f"{workflow}\n"
            f"Problem id: `{problem.problem_id}`\n"
            f"Language: `{problem.language}`\n"
            f"Time limit: `{problem.timeout_seconds}s`\n\n"
            "Original problem statement:\n\n"
            f"{problem.statement.rstrip()}\n"
        )
        task_paths.instruction_path.write_text(instruction, encoding="utf-8")

    def _write_environment(
        self,
        task_paths: "TaskPaths",
        problem: FrontierCS20Problem,
        *,
        verifier_token: str,
    ) -> None:
        env_dir = task_paths.environment_dir
        dockerfile = (self.template_dir / "environment" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        image = self.docker_image or problem.docker_image
        judge_image = self.docker_image or problem.judge_docker_image or image
        runtime = problem.config.get("runtime", {}) or {}
        apt_package_names = [
            str(pkg)
            for pkg in [
                *(runtime.get("apt_packages", []) or []),
                *(runtime.get("judge_apt_packages", []) or []),
            ]
        ]
        apt_packages = " ".join(dict.fromkeys(apt_package_names))
        extra_apt_install = (
            f"apt-get install -y --no-install-recommends {apt_packages} &&"
            if apt_packages
            else ": &&"
        )
        judge_pip_package_names = _judge_pip_package_names(
            runtime,
            problem_id=problem.problem_id,
        )
        agent_pip_package_names = [
            *_agent_pip_package_names(runtime, problem_id=problem.problem_id),
            *judge_pip_package_names,
        ]
        agent_pip_packages = " ".join(dict.fromkeys(agent_pip_package_names))
        judge_pip_packages = " ".join(dict.fromkeys(judge_pip_package_names))
        agent_pip_install = (
            f"pip3 install --break-system-packages {agent_pip_packages} &&"
            if agent_pip_packages
            else ": &&"
        )
        judge_pip_install = (
            f"pip3 install --break-system-packages {judge_pip_packages} &&"
            if judge_pip_packages
            else ": &&"
        )
        env_dir.joinpath("Dockerfile").write_text(
            dockerfile.replace("{base_image}", image).replace(
                "{extra_apt_install}", extra_apt_install
            ).replace(
                "{extra_pip_install}", agent_pip_install
            ).replace(
                "{visible_input_stages}",
                self._visible_input_stages(problem, default_image=judge_image),
            ).replace(
                "{visible_input_copies}",
                self._visible_input_copies(problem),
            ),
            encoding="utf-8",
        )

        for name in ("readme", "config.yaml"):
            src = problem.problem_dir / name
            if src.exists():
                shutil.copy2(src, env_dir / name)
        (env_dir / "task_config.json").write_text(
            json.dumps(problem.config, indent=2), encoding="utf-8"
        )
        self._write_submission_config(env_dir, problem)
        harbor_app_dir = problem.problem_dir / "harbor" / "app"
        generated_harbor_app_dir = env_dir / "harbor_app"
        generated_harbor_app_dir.mkdir(parents=True, exist_ok=True)
        has_public_assets = _public_assets_opted_in(harbor_app_dir)
        if has_public_assets:
            _snapshot_public_assets(harbor_app_dir, generated_harbor_app_dir)
        if harbor_app_dir.exists():
            shutil.copytree(
                harbor_app_dir,
                generated_harbor_app_dir,
                dirs_exist_ok=True,
                ignore=_root_app_copy_ignore(
                    harbor_app_dir,
                    exclude_input=bool(self._visible_inputs(problem)),
                    exclude_public=has_public_assets,
                ),
            )

        judge_public_assets = ""
        if has_public_assets:
            judge_public_assets = (
                "COPY harbor_app/public/ /judge/public/\n"
                "ENV FRONTIER_PUBLIC_DIR=/judge/public\n"
            )

        judge_dockerfile = (
            self.template_dir / "environment" / "Dockerfile.judge"
        ).read_text(encoding="utf-8")
        judge_apt_packages = " ".join(
            str(pkg) for pkg in runtime.get("judge_apt_packages", []) or []
        )
        env_dir.joinpath("Dockerfile.judge").write_text(
            judge_dockerfile.replace("{base_image}", judge_image)
            .replace(
                "{judge_apt_packages_line}",
                f" {judge_apt_packages}" if judge_apt_packages else "",
            )
            .replace("{judge_pip_install}", judge_pip_install)
            .replace("{judge_public_assets}", judge_public_assets),
            encoding="utf-8",
        )
        environment = problem.config.get("environment", {}) or {}
        compose = (
            self.template_dir / "environment" / "docker-compose.yaml"
        ).read_text(encoding="utf-8")
        (env_dir / "docker-compose.yaml").write_text(
            compose.format(
                judge_cpus=int(environment.get("cpus", 2)),
                judge_memory_mb=int(environment.get("memory_mb", 4096)),
            ),
            encoding="utf-8",
        )
        judge_server = (
            self.template_dir / "environment" / "judge_server.py"
        ).read_text(encoding="utf-8")
        (env_dir / "judge_server.py").write_text(
            judge_server.replace("{verifier_token}", verifier_token),
            encoding="utf-8",
        )
        for name in (
            "AGENT.md",
            "submit.py",
            "submissions.py",
            "wait_submission.py",
            "cancel_submission.py",
        ):
            shutil.copy2(self.template_dir / "environment" / name, env_dir / name)
        # Kept in the build context for the judge image only; the main agent
        # image's Dockerfile does not copy this into /app.
        shutil.copy2(problem.problem_dir / "evaluator.py", env_dir / "problem_evaluator.py")
        for name in (
            "submit.sh",
            "submissions.sh",
            "wait_submission.sh",
            "cancel_submission.sh",
        ):
            script = env_dir / name
            shutil.copy2(self.template_dir / "environment" / name, script)
            script.chmod(0o755)

    def _write_submission_config(self, env_dir: Path, problem: FrontierCS20Problem) -> None:
        submission = dict(problem.config.get("submission", {}) or {})
        submission.setdefault("kind", "file")
        submission.setdefault("path", "/app/solution.py")
        submission.setdefault("exclude", [])
        (env_dir / "submission_config.json").write_text(
            json.dumps(submission, indent=2), encoding="utf-8"
        )

    def _visible_inputs(self, problem: FrontierCS20Problem) -> list[dict[str, str]]:
        runtime = problem.config.get("runtime", {}) or {}
        entries = runtime.get("visible_inputs", []) or []
        if not isinstance(entries, list):
            raise TypeError(f"{problem.problem_id}: runtime.visible_inputs must be a list")
        normalized: list[dict[str, str]] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise TypeError(
                    f"{problem.problem_id}: runtime.visible_inputs[{index}] must be a mapping"
                )
            source = str(entry.get("source") or entry.get("from_image_path") or "")
            destination = str(entry.get("destination") or entry.get("to_app_path") or "")
            image = str(entry.get("image") or entry.get("from_image") or "")
            if not source.startswith("/") or not destination.startswith("/"):
                raise ValueError(
                    f"{problem.problem_id}: visible input paths must be absolute"
                )
            for value in (source, destination, image):
                if value and any(ch.isspace() for ch in value):
                    raise ValueError(
                        f"{problem.problem_id}: visible input values may not contain whitespace"
                    )
            normalized.append(
                {"source": source, "destination": destination, "image": image}
            )
        return normalized

    def _visible_input_stages(
        self, problem: FrontierCS20Problem, *, default_image: str
    ) -> str:
        lines: list[str] = []
        for index, entry in enumerate(self._visible_inputs(problem)):
            image = entry["image"] or default_image
            lines.append(f"FROM {image} AS visible_input_{index}\n")
        return "".join(lines)

    def _visible_input_copies(self, problem: FrontierCS20Problem) -> str:
        lines: list[str] = []
        for index, entry in enumerate(self._visible_inputs(problem)):
            lines.append(
                "COPY --from=visible_input_{index} {source} {destination}\n".format(
                    index=index,
                    source=entry["source"],
                    destination=entry["destination"],
                )
            )
        return "".join(lines)

    def _write_tests(
        self,
        task_paths: "TaskPaths",
        problem: FrontierCS20Problem,
        *,
        verifier_token: str,
    ) -> None:
        tests_dir = task_paths.tests_dir
        shutil.copy2(self.template_dir / "tests" / "test.sh", tests_dir / "test.sh")
        evaluate_py = (self.template_dir / "tests" / "evaluate.py").read_text(
            encoding="utf-8"
        )
        (tests_dir / "evaluate.py").write_text(
            evaluate_py.replace("{verifier_token}", verifier_token),
            encoding="utf-8",
        )
        shutil.copy2(problem.problem_dir / "evaluator.py", tests_dir / "problem_evaluator.py")
        (tests_dir / "test.sh").chmod(0o755)

    def _write_solution(self, task_paths: "TaskPaths", problem: FrontierCS20Problem) -> None:
        solution_dir = task_paths.solution_dir
        submission = problem.config.get("submission", {}) or {}
        submission_path = str(submission.get("path", "/app/solution.py"))
        submission_suffix = Path(submission_path).suffix.lstrip(".")
        reference_candidates = []
        if submission_suffix:
            reference_candidates.append(problem.problem_dir / f"reference.{submission_suffix}")
        reference_candidates.append(problem.problem_dir / "reference.py")
        for reference in reference_candidates:
            if reference.exists():
                shutil.copy2(reference, solution_dir / "reference.py")
                break
        solve_sh = solution_dir / "solve.sh"
        solve_text = (self.template_dir / "solution" / "solve.sh").read_text(
            encoding="utf-8"
        )
        solve_submission_path = (
            submission_path if submission.get("kind", "file") != "directory" else "/app/solution.py"
        )
        solve_sh.write_text(
            solve_text.replace("/app/solution.py", solve_submission_path),
            encoding="utf-8",
        )
        solve_sh.chmod(0o755)

    def _write_task_config(self, task_paths: "TaskPaths", problem: FrontierCS20Problem) -> None:
        template = (self.template_dir / "task.toml").read_text(encoding="utf-8")
        environment = problem.config.get("environment", {}) or {}
        text = template.format(
            task_id=problem.task_id,
            problem_id=problem.problem_id,
            tag=problem.tag,
            timeout_sec=problem.timeout_seconds,
            agent_timeout_sec=max(10800, problem.timeout_seconds),
            environment_build_timeout_sec=float(
                environment.get("build_timeout_seconds", 600)
            ),
            cpus=int(environment.get("cpus", 2)),
            memory_mb=int(environment.get("memory_mb", 4096)),
            storage_mb=int(environment.get("storage_mb", 4096)),
        )
        try:
            from harbor.models.task.config import TaskConfig

            config = TaskConfig.model_validate_toml(text)
            config.source = "https://github.com/FrontierCS/Frontier-CS"
            text = config.model_dump_toml()
        except ImportError:
            pass
        task_paths.config_path.write_text(text, encoding="utf-8")
