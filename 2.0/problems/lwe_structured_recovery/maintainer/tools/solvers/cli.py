"""Canonical single-worker CLI for validated exact-recovery solvers."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from types import FunctionType, ModuleType
from typing import NoReturn, Sequence


_TASK_DIR = Path(__file__).resolve().parents[3]
_APP_DIR = _TASK_DIR / "harbor" / "app"
_PUBLIC_DIR = _APP_DIR / "public"
if str(_PUBLIC_DIR) not in sys.path:
    sys.path.insert(0, str(_PUBLIC_DIR))

# Import only the reviewed public facade. Solver modules remain lazy.
import lwe_instance as _lwe_instance  # noqa: E402,F401

from .registry import instantiate_solver, load_registry  # noqa: E402


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        self.exit(2, "error: invalid command line\n")


def _positive_seconds(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a finite positive number") from exc
    if not math.isfinite(parsed) or parsed <= 0.0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return parsed


def _nonnegative_integer(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return int(value)


def _single_thread(value: str) -> int:
    if value != "1":
        raise argparse.ArgumentTypeError("must be exactly 1")
    return 1


def _lower_sha256(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", value, flags=re.ASCII) is None:
        raise argparse.ArgumentTypeError("must be a lowercase SHA-256 digest")
    return value


def build_parser() -> argparse.ArgumentParser:
    records = load_registry()
    parser = _SanitizedArgumentParser(
        prog="python3 -m tools.solvers.cli",
        description="Structured-LWE exact-recovery worker",
        allow_abbrev=False,
    )
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--catalog-fd", type=_nonnegative_integer)
    parser.add_argument("--catalog-format", choices=("json", "jsonl"))
    parser.add_argument("--catalog-sha256", type=_lower_sha256)
    parser.add_argument("--instance", "--instance-id", dest="instance_id", required=True)
    parser.add_argument(
        "--solver",
        choices=tuple(record.solver_id for record in records),
        required=True,
    )
    parser.add_argument(
        "--expected-solver-revision",
        type=_lower_sha256,
        required=True,
    )
    parser.add_argument("--max-seconds", type=_positive_seconds, default=7200.0)
    parser.add_argument("--seed", type=_nonnegative_integer, default=0)
    parser.add_argument("--work-dir", type=Path, default=Path("/private/work"))
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument("--private-output", type=Path)
    destination.add_argument("--ledger", type=Path)
    parser.add_argument("--threads", type=_single_thread, default=1)
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    fd_contract = (args.catalog_fd, args.catalog_format, args.catalog_sha256)
    if any(value is not None for value in fd_contract) and not all(
        value is not None for value in fd_contract
    ):
        parser.error(
            "--catalog-fd, --catalog-format, and --catalog-sha256 must be supplied together"
        )
    return args


def load_catalog(args: argparse.Namespace):
    """Load a parsed catalog, preferring the exact inherited descriptor contract."""

    if args.catalog_fd is None:
        return _lwe_instance.Catalog.load(args.catalog)
    catalog = _lwe_instance.Catalog.load_fd(args.catalog_fd, args.catalog_format)
    if catalog.catalog_id != args.catalog_sha256:
        raise ValueError("catalog descriptor digest does not match --catalog-sha256")
    return catalog


def _resolve_solver(solver_id: str):
    records = tuple(
        record for record in load_registry() if record.solver_id == solver_id
    )
    if len(records) != 1:
        raise ValueError("solver is not in the canonical registry")
    return instantiate_solver(records[0])


def _load_merge_solution() -> FunctionType:
    """Load the exact script-adjacent ledger boundary without ambient imports."""

    source_path = _APP_DIR / "add_solution.py"
    flags = os.O_RDONLY | os.O_NOFOLLOW
    descriptor = os.open(source_path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > 256 * 1024:
            raise ImportError("ledger boundary source is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ImportError("ledger boundary source was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ImportError("ledger boundary source changed while reading")
        named = os.stat(source_path, follow_symlinks=False)
        if (
            not stat.S_ISREG(named.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or named.st_size != opened.st_size
        ):
            raise ImportError("ledger boundary source identity changed")
    finally:
        os.close(descriptor)
    try:
        code = compile(
            b"".join(chunks),
            str(source_path),
            "exec",
            dont_inherit=True,
            optimize=0,
        )
        namespace: dict[str, object] = {
            "__name__": "_lwe_structured_recovery_add_solution",
            "__file__": str(source_path),
            "__package__": None,
        }
        exec(code, namespace)
    except Exception as exc:
        raise ImportError("cannot load the canonical ledger boundary") from exc
    candidate = namespace.get("merge_solution")
    ledger_module = namespace.get("ledger")
    expected_ledger = (_PUBLIC_DIR / "lwe_challenge" / "ledger.py").resolve()
    try:
        observed_ledger = Path(ledger_module.__file__).resolve()
    except (AttributeError, OSError, TypeError) as exc:
        raise ImportError("canonical ledger dependency has no source identity") from exc
    if (
        type(candidate) is not FunctionType
        or candidate.__module__ != namespace["__name__"]
        or Path(candidate.__code__.co_filename) != source_path
        or not isinstance(ledger_module, ModuleType)
        or observed_ledger != expected_ledger
    ):
        raise ImportError("canonical ledger boundary identity is inconsistent")
    return candidate


def _solver_revision(solver: object) -> str:
    from .registry import require_registry_instance

    return require_registry_instance(solver).implementation_digest


def _public_secret_domain_size(instance: object) -> int:
    n = instance.n
    q = instance.q
    predicate = instance.secret_predicate_kind
    alphabet = tuple(instance.secret_alphabet)
    minimum = instance.secret_min_nonzero
    maximum = instance.secret_max_nonzero
    if (
        type(n) is not int
        or n < 1
        or type(q) is not int
        or q < 2
        or type(minimum) is not int
        or type(maximum) is not int
        or not 0 <= minimum <= maximum <= n
    ):
        raise ValueError("public secret domain is invalid")
    if predicate == "mod_q":
        nonzero_choices = q - 1
        zero_available = True
    elif predicate == "alphabet":
        if not alphabet or any(type(value) is not int for value in alphabet):
            raise ValueError("public secret alphabet is invalid")
        nonzero_choices = len({value for value in alphabet if value != 0})
        zero_available = 0 in alphabet
    else:
        raise ValueError("public secret predicate is unsupported")
    total = 0
    for weight in range(minimum, maximum + 1):
        if weight < n and not zero_available:
            continue
        if weight > 0 and nonzero_choices == 0:
            continue
        total += math.comb(n, weight) * nonzero_choices**weight
    if total < 1:
        raise ValueError("public secret domain is empty")
    return total


def _exhaustion_payload(
    *,
    instance: object,
    solver: object,
    solver_revision: str,
    request: object,
    result: object,
) -> dict[str, object]:
    domain_size = _public_secret_domain_size(instance)
    certificate_id = result.detail.get("certificate_id")
    certificate_digest = result.detail.get("certificate_digest")
    if type(certificate_id) is not str or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
        certificate_id,
        flags=re.ASCII,
    ) is None or type(certificate_digest) is not str or re.fullmatch(
        r"[0-9a-f]{64}", certificate_digest, flags=re.ASCII
    ) is None:
        raise ValueError("exhaustion has no stable public certificate")
    unsigned = {
        "certificate_id": certificate_id,
        "certificate_version": 1,
        "instance_id": instance.instance_id,
        "instance_digest": instance.instance_digest,
        "solver_id": solver.solver_id,
        "solver_revision": solver_revision,
        "solver_seed": request.seed,
        "domain_size": domain_size,
        "range_start": 0,
        "range_stop": domain_size,
    }
    certificate = {
        **unsigned,
        "certificate_digest": hashlib.sha256(_canonical_json(unsigned)).hexdigest(),
    }
    return {"status": "EXHAUSTED", "certificate": certificate}


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _open_directory_nofollow(path: Path) -> int:
    if not path.is_absolute() or not hasattr(os, "O_DIRECTORY") or not hasattr(
        os, "O_NOFOLLOW"
    ):
        raise OSError("secure private-output directories are unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(os.sep, flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("private-output parent is not a directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _private_output_location(path: Path, work_dir: Path) -> Path:
    absolute_work = Path(os.path.abspath(work_dir))
    absolute_output = Path(os.path.abspath(path))
    try:
        relative = absolute_output.relative_to(absolute_work)
    except ValueError as exc:
        raise ValueError("private output must remain inside work-dir") from exc
    if not relative.parts or relative == Path("."):
        raise ValueError("private output must name a file inside work-dir")
    return absolute_output


def _preflight_private_output(path: Path, work_dir: Path) -> None:
    absolute_output = _private_output_location(path, work_dir)
    parent_descriptor = _open_directory_nofollow(absolute_output.parent)
    try:
        try:
            os.stat(
                absolute_output.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        raise FileExistsError("private output already exists")
    finally:
        os.close(parent_descriptor)


def _atomic_write_private_output(path: Path, payload: object, work_dir: Path) -> None:
    absolute_output = _private_output_location(path, work_dir)
    parent_descriptor = _open_directory_nofollow(absolute_output.parent)
    temporary_name = f".{absolute_output.name}.{secrets.token_hex(12)}.tmp"
    descriptor = -1
    published = False
    completed = False
    opened: os.stat_result | None = None
    try:
        try:
            os.stat(
                absolute_output.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("private output already exists")
        encoded = _canonical_json(payload)
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise OSError("private-output temporary is not regular")
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if type(written) is not int or written <= 0:
                raise OSError("private-output write was incomplete")
            offset += written
        os.fsync(descriptor)
        named_temporary = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(named_temporary.st_mode)
            or (named_temporary.st_dev, named_temporary.st_ino)
            != (opened.st_dev, opened.st_ino)
            or named_temporary.st_mode != opened.st_mode
            or named_temporary.st_nlink != 1
        ):
            raise OSError("private-output temporary identity changed")
        os.link(
            temporary_name,
            absolute_output.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published = True
        named_temporary = os.stat(
            temporary_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        named_output = os.stat(
            absolute_output.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if any(
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino)
            or metadata.st_mode != opened.st_mode
            or metadata.st_nlink != 2
            for metadata in (named_temporary, named_output, os.fstat(descriptor))
        ):
            raise OSError("private-output publication identity changed")
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        retained = os.fstat(descriptor)
        if (
            (retained.st_dev, retained.st_ino) != (opened.st_dev, opened.st_ino)
            or retained.st_mode != opened.st_mode
            or retained.st_nlink != 1
        ):
            raise OSError("private-output publication identity changed")
        os.fsync(parent_descriptor)
        completed = True
    finally:
        if not completed:
            if descriptor >= 0:
                try:
                    os.ftruncate(descriptor, 0)
                    os.fsync(descriptor)
                except OSError:
                    pass
            if published:
                try:
                    os.unlink(absolute_output.name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _execute(args: argparse.Namespace) -> int:
    from .api import SolveRequest, SolveStatus

    if (args.private_output is None) == (args.ledger is None):
        raise ValueError("exactly one private destination is required")
    if type(args.threads) is not int or args.threads != 1:
        raise ValueError("worker thread count must be exactly one")
    catalog = load_catalog(args)
    instance = catalog.get(args.instance_id)
    solver = _resolve_solver(args.solver)
    if getattr(solver, "solver_id", None) != args.solver:
        raise ValueError("solver ID does not match the canonical registry")
    solver_revision = _solver_revision(solver)
    if solver_revision != args.expected_solver_revision:
        raise ValueError("solver revision does not match the expected binding")
    request = SolveRequest(
        seed=args.seed,
        max_seconds=args.max_seconds,
        work_dir=args.work_dir,
        single_worker=args.threads == 1,
        parameters={
            "clean_subset_cap": 1_000_000,
            "work_unit_cap": 10_000_000_000,
        },
        checkpoint_every_work_units=10_000_000,
    )
    merge_solution = _load_merge_solution() if args.ledger is not None else None
    if args.private_output is not None:
        _preflight_private_output(args.private_output, request.work_dir)
    result = solver.solve(instance, request)
    if result.status is SolveStatus.CENSORED and args.private_output is not None:
        reason = result.detail.get("reason", result.detail.get("code"))
        if reason not in {"time_cap", "timeout"}:
            raise ValueError("solver censoring is not a scheduled wall-time cap")
        _atomic_write_private_output(
            args.private_output,
            {
                "status": "CENSORED",
                "censor_cap": request.max_seconds,
                "censor_unit": "seconds",
                "reason": "wall_cap",
            },
            request.work_dir,
        )
        return 0
    if result.status is SolveStatus.EXHAUSTED and args.private_output is not None:
        _atomic_write_private_output(
            args.private_output,
            _exhaustion_payload(
                instance=instance,
                solver=solver,
                solver_revision=solver_revision,
                request=request,
                result=result,
            ),
            request.work_dir,
        )
        return 0
    if result.status is not SolveStatus.SUCCESS or result.secret is None:
        return 2
    if args.private_output is not None:
        _atomic_write_private_output(
            args.private_output,
            {"secret": list(result.secret)},
            request.work_dir,
        )
        return 0
    if merge_solution is None:
        raise ValueError("canonical ledger boundary is unavailable")
    solved_count = merge_solution(args.ledger, args.instance_id, result.secret)
    print(f"solved count: {solved_count}")
    print("submit new solutions immediately")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        return _execute(args)
    except Exception:
        sys.stderr.write("error: worker failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
