from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_SRC = REPO_ROOT / "adapters" / "frontier-cs-2.0" / "src"
sys.path.insert(0, str(ADAPTER_SRC))
try:
    import frontier_cs_2_0.adapter as adapter_module
    from frontier_cs_2_0.adapter import FrontierCS20Adapter
finally:
    assert sys.path.pop(0) == str(ADAPTER_SRC)


PUBLIC_PAYLOAD = b'{"instance_id":"fixture_0001"}\n'


def _write_fixture_repo(tmp_path: Path, *, include_public: bool) -> Path:
    repo = tmp_path / "repo"
    problem = repo / "2.0" / "problems" / "json_fixture"
    app = problem / "harbor" / "app"
    solver_dir = app / "tools" / "solvers"
    solver_dir.mkdir(parents=True)
    problem.joinpath("config.yaml").write_text(
        """\
tag: security
runtime:
  language: json
  timeout_seconds: 300
  pip_packages:
    - numpy==2.1.3
  judge_pip_packages:
    - jsonschema==4.23.0
  docker:
    image: ubuntu:24.04
submission:
  kind: file
  path: /app/solution.json
""",
        encoding="utf-8",
    )
    problem.joinpath("readme").write_text("# JSON fixture\n", encoding="utf-8")
    problem.joinpath("evaluator.py").write_text(
        "def evaluate(solution_path):\n"
        "    return 0.0, 0.0, 'fixture'\n",
        encoding="utf-8",
    )
    problem.joinpath("reference.json").write_text(
        '{"schema_version": 1, "solutions": []}\n',
        encoding="utf-8",
    )
    solver_dir.joinpath("reference_attack.py").write_text(
        "raise SystemExit('fixture solver must not enter the judge image')\n",
        encoding="utf-8",
    )
    analyses = app / "analyses"
    analyses.mkdir()
    analyses.joinpath("fixture_0001.md").write_text(
        "# Fixture analysis\n",
        encoding="utf-8",
    )
    if include_public:
        public = app / "public"
        public.mkdir()
        public.joinpath("catalog.jsonl").write_bytes(PUBLIC_PAYLOAD)
    return repo


def _generate_fixture(tmp_path: Path, *, include_public: bool) -> Path:
    repo = _write_fixture_repo(tmp_path, include_public=include_public)
    generated = FrontierCS20Adapter(
        repo,
        tmp_path / "generated",
        task_ids=["json_fixture"],
    ).run()
    assert len(generated) == 1
    return generated[0]


def test_public_assets_are_staged_for_agent_and_copied_to_judge(
    tmp_path: Path,
) -> None:
    task = _generate_fixture(tmp_path, include_public=True)
    environment = task / "environment"
    judge = environment.joinpath("Dockerfile.judge").read_text(encoding="utf-8")
    agent = environment.joinpath("Dockerfile").read_text(encoding="utf-8")

    assert environment.joinpath(
        "harbor_app", "public", "catalog.jsonl"
    ).read_bytes() == PUBLIC_PAYLOAD
    assert "COPY harbor_app/ /app/" in agent
    assert "COPY harbor_app/public/ /judge/public/" in judge
    assert "ENV FRONTIER_PUBLIC_DIR=/judge/public" in judge
    assert "COPY harbor_app/ /judge/" not in judge
    assert "harbor_app/tools" not in judge
    assert "harbor_app/analyses" not in judge
    assert "{judge_public_assets}" not in judge


def test_agent_only_pip_packages_do_not_enter_judge(tmp_path: Path) -> None:
    task = _generate_fixture(tmp_path, include_public=False)
    environment = task / "environment"
    judge = environment.joinpath("Dockerfile.judge").read_text(encoding="utf-8")
    agent = environment.joinpath("Dockerfile").read_text(encoding="utf-8")

    assert "numpy==2.1.3" in agent
    assert "jsonschema==4.23.0" in agent
    assert "numpy==2.1.3" not in judge
    assert "jsonschema==4.23.0" in judge


def test_task_without_public_assets_keeps_existing_judge_shape(
    tmp_path: Path,
) -> None:
    task = _generate_fixture(tmp_path, include_public=False)
    environment = task / "environment"
    judge = environment.joinpath("Dockerfile.judge").read_text(encoding="utf-8")

    assert not environment.joinpath("harbor_app", "public").exists()
    assert "COPY harbor_app/public/ /judge/public/" not in judge
    assert "FRONTIER_PUBLIC_DIR" not in judge
    assert "{judge_public_assets}" not in judge
    assert "COPY judge_server.py problem_evaluator.py task_config.json /judge/" in judge


def test_nondirectory_public_entry_keeps_legacy_agent_only_shape(
    tmp_path: Path,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=False)
    public_file = repo / "2.0/problems/json_fixture/harbor/app/public"
    public_file.write_bytes(PUBLIC_PAYLOAD)

    task = FrontierCS20Adapter(
        repo,
        tmp_path / "generated",
        task_ids=["json_fixture"],
    ).run()[0]
    staged = task / "environment/harbor_app/public"
    judge = task.joinpath("environment/Dockerfile.judge").read_text(
        encoding="utf-8"
    )

    assert staged.is_file()
    assert staged.read_bytes() == PUBLIC_PAYLOAD
    assert "COPY harbor_app/public/ /judge/public/" not in judge
    assert "FRONTIER_PUBLIC_DIR" not in judge


def test_json_reference_bytes_reach_configured_submission_path(
    tmp_path: Path,
) -> None:
    task = _generate_fixture(tmp_path, include_public=True)

    assert task.joinpath("solution", "reference.py").read_text(
        encoding="utf-8"
    ) == '{"schema_version": 1, "solutions": []}\n'
    assert "cp /solution/reference.py /app/solution.json" in task.joinpath(
        "solution", "solve.sh"
    ).read_text(encoding="utf-8")


def test_public_assets_reject_symlinks_before_staging(tmp_path: Path) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    outside = tmp_path / "outside-secret"
    outside.write_text("must not enter either image", encoding="utf-8")
    public = repo / "2.0/problems/json_fixture/harbor/app/public"
    nested = public / "nested"
    nested.mkdir()
    nested.joinpath("escape").symlink_to(outside)

    with pytest.raises(ValueError, match="public assets may not contain symlinks"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()


def test_public_assets_reject_symlinked_app_ancestor_before_staging(
    tmp_path: Path,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    app = repo / "2.0/problems/json_fixture/harbor/app"
    real_app = tmp_path / "real-app"
    app.rename(real_app)
    app.symlink_to(real_app, target_is_directory=True)

    with pytest.raises(ValueError, match="public assets source path.*symlink"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    staged_public = tmp_path.joinpath(
        "generated",
        "frontier-cs-2-0-json-fixture",
        "environment",
        "harbor_app",
        "public",
    )
    assert not os.path.lexists(staged_public)


def test_task_without_public_assets_preserves_legacy_symlink_dereference(
    tmp_path: Path,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=False)
    outside = tmp_path / "outside-tool.py"
    outside.write_text("legacy symlink target\n", encoding="utf-8")
    source_link = repo.joinpath(
        "2.0/problems/json_fixture/harbor/app/tools/external-tool.py"
    )
    source_link.symlink_to(outside)

    task = FrontierCS20Adapter(
        repo,
        tmp_path / "generated",
        task_ids=["json_fixture"],
    ).run()[0]
    staged_link = task / "environment/harbor_app/tools/external-tool.py"

    assert not staged_link.is_symlink()
    assert staged_link.read_text(encoding="utf-8") == "legacy symlink target\n"


def test_public_file_swap_at_open_boundary_cannot_escape_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    public_file = repo / "2.0/problems/json_fixture/harbor/app/public/catalog.jsonl"
    outside = tmp_path / "outside-after-validation"
    outside.write_text("must not enter the staged public tree", encoding="utf-8")
    swapped = False

    def swap_then_open(name: str, flags: int, *, dir_fd: int) -> int:
        nonlocal swapped
        if name == "catalog.jsonl" and not swapped:
            swapped = True
            public_file.unlink()
            public_file.symlink_to(outside)
        return os.open(name, flags, dir_fd=dir_fd)

    monkeypatch.setattr(
        adapter_module,
        "_open_public_source_entry",
        swap_then_open,
        raising=False,
    )

    with pytest.raises(ValueError, match="public assets may not contain symlinks"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()
    assert swapped
    assert not os.path.lexists(
        tmp_path
        / "generated/frontier-cs-2-0-json-fixture/environment/harbor_app/public"
    )


def test_destination_parent_swap_cannot_redirect_public_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    generated_app = tmp_path.joinpath(
        "generated/frontier-cs-2-0-json-fixture/environment/harbor_app"
    )
    moved_app = tmp_path / "moved-harbor-app"
    outside = tmp_path / "outside-destination"
    outside.mkdir()
    swapped = False

    def swap_then_create(parent_fd: int) -> tuple[str, int]:
        nonlocal swapped
        generated_app.rename(moved_app)
        generated_app.symlink_to(outside, target_is_directory=True)
        swapped = True
        name = ".public-snapshot-test"
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        descriptor = os.open(
            name,
            adapter_module._DESTINATION_DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
        return name, descriptor

    monkeypatch.setattr(
        adapter_module,
        "_create_private_public_destination",
        swap_then_create,
        raising=False,
    )

    with pytest.raises(ValueError, match="public assets destination changed"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    assert swapped
    assert list(outside.iterdir()) == []


def test_private_snapshot_entry_swap_is_rejected_without_deleting_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    generated_app = tmp_path.joinpath(
        "generated/frontier-cs-2-0-json-fixture/environment/harbor_app"
    )
    displaced_name = ".displaced-original-snapshot"
    replacement_name: str | None = None
    real_finalize = getattr(adapter_module, "_finalize_public_snapshot", None)

    def swap_then_finalize(
        parent_fd: int,
        temporary_name: str,
        snapshot_fd: int,
        manifest: adapter_module.PublicSnapshotManifest,
    ) -> None:
        nonlocal replacement_name
        replacement_name = temporary_name
        os.rename(
            temporary_name,
            displaced_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.mkdir(temporary_name, mode=0o700, dir_fd=parent_fd)
        replacement_fd = os.open(
            temporary_name,
            adapter_module._DESTINATION_DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
        try:
            marker_fd = os.open(
                "replacement-marker",
                adapter_module._DESTINATION_FILE_FLAGS,
                0o600,
                dir_fd=replacement_fd,
            )
            os.close(marker_fd)
        finally:
            os.close(replacement_fd)
        if real_finalize is not None:
            real_finalize(parent_fd, temporary_name, snapshot_fd, manifest)

    monkeypatch.setattr(
        adapter_module,
        "_finalize_public_snapshot",
        swap_then_finalize,
        raising=False,
    )

    with pytest.raises(ValueError, match="private destination changed"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    assert replacement_name is not None
    assert not os.path.lexists(generated_app / "public")
    assert generated_app.joinpath(replacement_name, "replacement-marker").is_file()


def test_rename_boundary_swap_rejects_unrecognized_public_without_judge_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    environment = tmp_path.joinpath(
        "generated/frontier-cs-2-0-json-fixture/environment"
    )
    generated_app = environment / "harbor_app"
    displaced_name = ".displaced-installed-snapshot"
    real_rename = getattr(adapter_module, "_rename_public_snapshot_entry", None)
    swapped = False

    def rename_then_replace(parent_fd: int, temporary_name: str) -> None:
        nonlocal swapped
        if real_rename is None:
            return
        real_rename(parent_fd, temporary_name)
        os.rename(
            "public",
            displaced_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.mkdir("public", mode=0o700, dir_fd=parent_fd)
        replacement_fd = os.open(
            "public",
            adapter_module._DESTINATION_DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
        try:
            marker_fd = os.open(
                "replacement-marker",
                adapter_module._DESTINATION_FILE_FLAGS,
                0o600,
                dir_fd=replacement_fd,
            )
            os.close(marker_fd)
        finally:
            os.close(replacement_fd)
        swapped = True

    monkeypatch.setattr(
        adapter_module,
        "_rename_public_snapshot_entry",
        rename_then_replace,
        raising=False,
    )

    with pytest.raises(ValueError, match="installed public assets changed"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    assert swapped
    assert generated_app.joinpath("public/replacement-marker").is_file()
    assert not environment.joinpath("Dockerfile.judge").exists()


def test_nested_destination_swap_between_mkdir_and_open_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    public = repo / "2.0/problems/json_fixture/harbor/app/public"
    nested = public / "nested"
    nested.mkdir()
    nested.joinpath("payload.txt").write_text("payload\n", encoding="utf-8")
    generated_app = tmp_path.joinpath(
        "generated/frontier-cs-2-0-json-fixture/environment/harbor_app"
    )
    real_open = getattr(
        adapter_module,
        "_open_created_public_destination_directory",
        None,
    )
    swapped = False

    def swap_then_open(
        name: str,
        *,
        parent_fd: int,
        expected: os.stat_result,
    ) -> int:
        nonlocal swapped
        if name == "nested" and not swapped:
            os.rename(
                name,
                ".displaced-nested",
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            swapped = True
        if real_open is not None:
            return real_open(name, parent_fd=parent_fd, expected=expected)
        return os.open(
            name,
            adapter_module._DESTINATION_DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )

    monkeypatch.setattr(
        adapter_module,
        "_open_created_public_destination_directory",
        swap_then_open,
        raising=False,
    )

    with pytest.raises(ValueError, match="destination changed"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    assert swapped
    assert not os.path.lexists(generated_app / "public")


def test_injected_snapshot_child_is_rejected_before_judge_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    environment = tmp_path.joinpath(
        "generated/frontier-cs-2-0-json-fixture/environment"
    )
    generated_app = environment / "harbor_app"
    real_rename = adapter_module._rename_public_snapshot_entry
    injected = False

    def rename_then_inject(parent_fd: int, temporary_name: str) -> None:
        nonlocal injected
        real_rename(parent_fd, temporary_name)
        public_fd = os.open(
            "public",
            adapter_module._DESTINATION_DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
        try:
            injected_fd = os.open(
                "injected-extra",
                adapter_module._DESTINATION_FILE_FLAGS,
                0o600,
                dir_fd=public_fd,
            )
            os.close(injected_fd)
        finally:
            os.close(public_fd)
        injected = True

    monkeypatch.setattr(
        adapter_module,
        "_rename_public_snapshot_entry",
        rename_then_inject,
    )

    with pytest.raises(ValueError, match="snapshot contents changed"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    assert injected
    assert generated_app.joinpath("public/injected-extra").is_file()
    assert not environment.joinpath("Dockerfile.judge").exists()


def test_staged_file_rewrite_at_finalize_boundary_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    environment = tmp_path.joinpath(
        "generated/frontier-cs-2-0-json-fixture/environment"
    )
    real_rename = adapter_module._rename_public_snapshot_entry
    rewritten = False

    def rewrite_then_rename(parent_fd: int, temporary_name: str) -> None:
        nonlocal rewritten
        snapshot_fd = os.open(
            temporary_name,
            adapter_module._DESTINATION_DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
        try:
            file_fd = os.open(
                "catalog.jsonl",
                os.O_WRONLY
                | os.O_TRUNC
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=snapshot_fd,
            )
            try:
                os.write(file_fd, b"rewritten-at-finalize\n")
            finally:
                os.close(file_fd)
        finally:
            os.close(snapshot_fd)
        rewritten = True
        real_rename(parent_fd, temporary_name)

    monkeypatch.setattr(
        adapter_module,
        "_rename_public_snapshot_entry",
        rewrite_then_rename,
    )

    with pytest.raises(ValueError, match="snapshot contents changed"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    assert rewritten
    assert not environment.joinpath("Dockerfile.judge").exists()


def test_in_place_source_rewrite_during_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    public_file = repo / "2.0/problems/json_fixture/harbor/app/public/catalog.jsonl"
    rewritten_payload = PUBLIC_PAYLOAD + b"mutated-during-read\n"
    rewritten = False

    def rewrite_then_read(descriptor: int, size: int) -> bytes:
        nonlocal rewritten
        if not rewritten:
            public_file.write_bytes(rewritten_payload)
            rewritten = True
        return os.read(descriptor, size)

    monkeypatch.setattr(
        adapter_module,
        "_read_public_source_chunk",
        rewrite_then_read,
        raising=False,
    )

    with pytest.raises(ValueError, match="public asset changed during snapshot"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    assert rewritten


def test_visible_inputs_exclude_only_root_input_from_public_snapshot(
    tmp_path: Path,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    problem = repo / "2.0/problems/json_fixture"
    config = problem / "config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "  docker:\n",
            "  visible_inputs:\n"
            "    - source: /fixture-input\n"
            "      destination: /app/input\n"
            "  docker:\n",
        ),
        encoding="utf-8",
    )
    root_input = problem / "harbor/app/input"
    root_input.mkdir()
    root_input.joinpath("hidden.txt").write_text("hidden\n", encoding="utf-8")
    public = problem / "harbor/app/public"
    public_input = public / "input"
    public_input.mkdir()
    public_input.joinpath("kept.txt").write_text("kept\n", encoding="utf-8")
    nested_input = public / "nested/input"
    nested_input.mkdir(parents=True)
    nested_input.joinpath("also-kept.txt").write_text(
        "also kept\n", encoding="utf-8"
    )

    task = FrontierCS20Adapter(
        repo,
        tmp_path / "generated",
        task_ids=["json_fixture"],
    ).run()[0]
    staged = task / "environment/harbor_app"

    assert not staged.joinpath("input").exists()
    assert staged.joinpath("public/input/kept.txt").read_text(
        encoding="utf-8"
    ) == "kept\n"
    assert staged.joinpath("public/nested/input/also-kept.txt").read_text(
        encoding="utf-8"
    ) == "also kept\n"


@pytest.mark.parametrize(
    ("include_public", "expected"),
    (
        (
            True,
            [
                "COPY judge_server.py problem_evaluator.py task_config.json /judge/",
                "COPY harbor_app/public/ /judge/public/",
            ],
        ),
        (
            False,
            ["COPY judge_server.py problem_evaluator.py task_config.json /judge/"],
        ),
    ),
)
def test_judge_dockerfile_has_only_the_declared_copy_instructions(
    tmp_path: Path,
    include_public: bool,
    expected: list[str],
) -> None:
    task = _generate_fixture(tmp_path, include_public=include_public)
    judge = task.joinpath("environment/Dockerfile.judge").read_text(
        encoding="utf-8"
    )

    assert [line for line in judge.splitlines() if line.startswith("COPY ")] == expected


def test_public_assets_reject_nonregular_files_before_staging(
    tmp_path: Path,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    fifo = repo / "2.0/problems/json_fixture/harbor/app/public/fixture.fifo"
    os.mkfifo(fifo)

    with pytest.raises(ValueError, match="only directories and regular files"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()


def test_public_assets_reject_trees_larger_than_64_mib(tmp_path: Path) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    oversized = repo / "2.0/problems/json_fixture/harbor/app/public/oversized.bin"
    with oversized.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)

    with pytest.raises(ValueError, match="64 MiB"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()

    staged_app = tmp_path.joinpath(
        "generated/frontier-cs-2-0-json-fixture/environment/harbor_app"
    )
    assert not any(
        entry.name.startswith(".public-snapshot-")
        for entry in staged_app.iterdir()
    )


def test_agent_pip_packages_require_exact_safe_pins(tmp_path: Path) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=False)
    config = repo / "2.0/problems/json_fixture/config.yaml"

    for invalid in ("numpy", "numpy>=2.1.3", "numpy==2.1.3;whoami", "numpy ==2.1.3"):
        text = config.read_text(encoding="utf-8")
        config.write_text(text.replace("numpy==2.1.3", invalid), encoding="utf-8")
        with pytest.raises(ValueError, match="runtime.pip_packages"):
            FrontierCS20Adapter(
                repo,
                tmp_path / f"generated-{invalid.replace('/', '-')}",
                task_ids=["json_fixture"],
            ).run()
        config.write_text(text, encoding="utf-8")


def test_bare_unpinned_judge_package_remains_supported(tmp_path: Path) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=False)
    config = repo / "2.0/problems/json_fixture/config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "jsonschema==4.23.0", "jsonschema"
        ),
        encoding="utf-8",
    )

    task = FrontierCS20Adapter(
        repo,
        tmp_path / "generated",
        task_ids=["json_fixture"],
    ).run()[0]

    assert "jsonschema" in task.joinpath(
        "environment", "Dockerfile.judge"
    ).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "invalid",
    (
        "jsonschema >=4.23.0",
        "jsonschema;whoami",
        "jsonschema>4.23.0",
    ),
)
def test_judge_pip_packages_reject_shell_syntax(
    tmp_path: Path,
    invalid: str,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=False)
    config = repo / "2.0/problems/json_fixture/config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "jsonschema==4.23.0", invalid
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="runtime.judge_pip_packages"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()


def test_config_without_agent_pip_packages_keeps_default_install_shape(
    tmp_path: Path,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=False)
    config = repo / "2.0/problems/json_fixture/config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "  pip_packages:\n    - numpy==2.1.3\n", ""
        ),
        encoding="utf-8",
    )

    task = FrontierCS20Adapter(
        repo,
        tmp_path / "generated",
        task_ids=["json_fixture"],
    ).run()[0]
    environment = task / "environment"
    agent = environment.joinpath("Dockerfile").read_text(encoding="utf-8")
    judge = environment.joinpath("Dockerfile.judge").read_text(encoding="utf-8")

    assert "numpy" not in agent
    assert "jsonschema==4.23.0" in agent
    assert "jsonschema==4.23.0" in judge
