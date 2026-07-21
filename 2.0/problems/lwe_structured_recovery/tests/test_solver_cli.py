from __future__ import annotations

import os
import json
import hashlib
import stat
import subprocess
import sys
from types import ModuleType
from pathlib import Path

import pytest

from tools.solvers import cli
from tools.solvers.api import ValidatedExactSolver, SolveResult


TASK_DIR = Path(__file__).resolve().parents[1]
APP_DIR = TASK_DIR / "harbor" / "app"
MAINTAINER_DIR = TASK_DIR / "maintainer"
SOLVER_REVISION = "a" * 64


def _run_lazy_import_probe(
    tmp_path: Path, action: str
) -> subprocess.CompletedProcess[str]:
    probe = (
        "import sys\n"
        "from tools.solvers import registry\n"
        "records = registry.load_registry()\n"
        "implementation_modules = {\n"
        "    record.entrypoint.partition(':')[0] for record in records\n"
        "}\n"
        "calls = []\n"
        "real_import_module = registry.importlib.import_module\n"
        "def tracked(name, package=None):\n"
        "    calls.append(name)\n"
        "    return real_import_module(name, package)\n"
        "registry.importlib.import_module = tracked\n"
        "before = set(sys.modules)\n"
        "from tools.solvers import cli\n"
        f"{action}\n"
        "after = set(sys.modules)\n"
        "assert implementation_modules.isdisjoint(calls)\n"
        "assert implementation_modules.isdisjoint(after - before)\n"
    )
    return subprocess.run(
        [sys.executable, "-c", probe],
        cwd=MAINTAINER_DIR,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(tmp_path),
            "LC_ALL": "C.UTF-8",
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_parser_accepts_public_contract_without_importing_solver(
    tmp_path: Path,
) -> None:
    completed = _run_lazy_import_probe(
        tmp_path,
        "args = cli.parse_args(["
        "'--catalog', '/public/catalog.json', "
        "'--instance-id', 'binary_fixture', "
        "'--solver', 'sparse_secret_enum', "
        f"'--expected-solver-revision', {SOLVER_REVISION!r}, "
        "'--max-seconds', '1.5', '--seed', '7', "
        "'--work-dir', '/private/work', "
        "'--private-output', '/private/work/result.json', "
        "'--threads', '1'])\n"
        "assert args.solver == 'sparse_secret_enum'\n"
        "assert args.threads == 1",
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_help_runs_without_pythonpath_and_without_solver_imports(tmp_path: Path) -> None:
    completed = _run_lazy_import_probe(
        tmp_path,
        "try:\n"
        "    cli.parse_args(['--help'])\n"
        "except SystemExit as exc:\n"
        "    assert exc.code == 0\n"
        "else:\n"
        "    raise AssertionError('--help did not exit')",
    )
    assert completed.returncode == 0, completed.stderr
    assert "exact-recovery worker" in completed.stdout
    assert "--solver" in completed.stdout
    assert "Traceback" not in completed.stderr


def test_packaged_fake_noop_executes_without_pythonpath_or_solver_imports(
    tmp_path: Path,
) -> None:
    output = tmp_path / "private-result.json"
    completed = _run_lazy_import_probe(
        tmp_path,
        "from tools.solvers.api import SolveResult\n"
        "class Verdict:\n"
        "    ok = True\n"
        "class Instance:\n"
        "    instance_id = 'toy-uniform'\n"
        "    def validate_secret(self, secret):\n"
        "        assert secret == (1,)\n"
        "        return Verdict()\n"
        "instance = Instance()\n"
        "class Catalog:\n"
        "    def get(self, instance_id):\n"
        "        assert instance_id == instance.instance_id\n"
        "        return instance\n"
        "class FakeNoopSolver:\n"
        "    solver_id = 'primal_bdd'\n"
        "    def solve(self, observed, request):\n"
        "        assert observed is instance\n"
        "        assert request.single_worker is True\n"
        "        return SolveResult.success(secret=(1,), "
        "elapsed_seconds=0.0, work_units=0)\n"
        "cli.load_catalog = lambda args: Catalog()\n"
        "cli._resolve_solver = lambda solver_id: FakeNoopSolver()\n"
        f"cli._solver_revision = lambda solver: {SOLVER_REVISION!r}\n"
        "assert cli.main(['--catalog', 'unused.json', '--instance', "
        "'toy-uniform', '--solver', 'primal_bdd', "
        f"'--expected-solver-revision', {SOLVER_REVISION!r}, '--work-dir', "
        f"{str(tmp_path)!r}, '--private-output', {str(output)!r}, "
        "'--threads', '1']) == 0\n"
        f"assert {str(output)!r} and __import__('pathlib').Path({str(output)!r}).read_bytes() "
        "== b'{\"secret\":[1]}\\n'",
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout == ""
    assert completed.stderr == ""


@pytest.mark.parametrize(
    "argv",
    [
        [
            "--catalog",
            "x",
            "--instance-id",
            "i",
            "--solver",
            "../bad",
            "--expected-solver-revision",
            SOLVER_REVISION,
        ],
        [
            "--catalog",
            "x",
            "--instance-id",
            "i",
            "--solver",
            "unknown",
            "--expected-solver-revision",
            SOLVER_REVISION,
        ],
        [
            "--catalog",
            "x",
            "--instance-id",
            "i",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--max-seconds",
            "nan",
        ],
    ],
)
def test_invalid_arguments_are_sanitized(argv: list[str], capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.parse_args(argv)
    assert caught.value.code == 2
    stderr = capsys.readouterr().err
    assert "Traceback" not in stderr
    assert str(APP_DIR) not in stderr


@pytest.mark.parametrize(
    "revision",
    [None, "A" * 64, "a" * 63, "g" * 64],
)
def test_expected_solver_revision_is_required_lowercase_sha256(
    revision: str | None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    argv = [
        "--catalog",
        "catalog.json",
        "--instance",
        "toy-uniform",
        "--solver",
        "primal_bdd",
    ]
    if revision is not None:
        argv.extend(("--expected-solver-revision", revision))
    with pytest.raises(SystemExit) as caught:
        cli.parse_args(argv)
    assert caught.value.code == 2
    assert capsys.readouterr().err == "error: invalid command line\n"


def test_invalid_argument_values_are_not_reflected(capsys) -> None:
    canary = "PRIVATE-SOLVER-CANARY"
    with pytest.raises(SystemExit) as caught:
        cli.parse_args(
            [
                "--catalog",
                "catalog.json",
                "--instance",
                "toy-uniform",
                "--solver",
                canary,
                "--expected-solver-revision",
                SOLVER_REVISION,
                "--private-output",
                "/private/result.json",
            ]
        )
    assert caught.value.code == 2
    stderr = capsys.readouterr().err
    assert stderr == "error: invalid command line\n"
    assert canary not in stderr


def test_cli_uses_adjacent_registry_after_chdir(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    parser = cli.build_parser()
    choices = parser._option_string_actions["--solver"].choices
    assert set(choices) == {record.solver_id for record in cli.load_registry()}


def test_parser_rejects_conflicting_private_destinations(capsys) -> None:
    common = [
        "--catalog",
        "catalog.json",
        "--instance",
        "toy-uniform",
        "--solver",
        "primal_bdd",
        "--expected-solver-revision",
        SOLVER_REVISION,
    ]
    parsed = cli.parse_args(common)
    assert parsed.private_output is None
    assert parsed.ledger is None
    assert parsed.max_seconds == 7200.0
    assert cli.parse_args([*common, "--max-seconds", "17.5"]).max_seconds == 17.5
    with pytest.raises(SystemExit) as conflicting:
        cli.parse_args(
            [
                *common,
                "--private-output",
                "/private/result.json",
                "--ledger",
                "/private/solution.json",
            ]
        )
    assert conflicting.value.code == 2
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("threads", ["0", "2", "01", "+1", "1.0"])
def test_parser_rejects_every_noncanonical_thread_count(
    threads: str, capsys
) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.parse_args(
            [
                "--catalog",
                "catalog.json",
                "--instance",
                "toy-uniform",
                "--solver",
                "primal_bdd",
                "--expected-solver-revision",
                SOLVER_REVISION,
                "--private-output",
                "/private/result.json",
                "--threads",
                threads,
            ]
        )
    assert caught.value.code == 2
    assert capsys.readouterr().err == "error: invalid command line\n"


def test_catalog_descriptor_contract_precedes_path_and_checks_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    calls: list[tuple[object, ...]] = []

    class Loaded:
        catalog_id = digest

    class CatalogApi:
        @classmethod
        def load(cls, path: Path) -> object:
            calls.append(("path", path))
            raise AssertionError("catalog path must not be reopened")

        @classmethod
        def load_fd(cls, descriptor: int, catalog_format: str) -> Loaded:
            calls.append(("fd", descriptor, catalog_format))
            return Loaded()

    monkeypatch.setattr(cli._lwe_instance, "Catalog", CatalogApi)
    args = cli.parse_args(
        [
            "--catalog",
            "catalog.json",
            "--catalog-fd",
            "7",
            "--catalog-format",
            "json",
            "--catalog-sha256",
            digest,
            "--instance",
            "toy-uniform",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--private-output",
            "/private/result.json",
        ]
    )

    assert cli.load_catalog(args).catalog_id == digest
    assert calls == [("fd", 7, "json")]

    args.catalog_sha256 = "b" * 64
    with pytest.raises(ValueError, match="digest"):
        cli.load_catalog(args)


def test_main_runs_solver_body_without_authorization_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    entered_recovery = False

    class FakeValidatedSolver(ValidatedExactSolver):
        solver_id = "primal_bdd"

        def _solve(self, instance: object, request: object) -> SolveResult:
            nonlocal entered_recovery
            entered_recovery = True
            return SolveResult.error(elapsed_seconds=0.0, work_units=0)

    class Catalog:
        def get(self, _instance_id: str) -> object:
            return object()

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", lambda _solver_id: FakeValidatedSolver())
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: SOLVER_REVISION)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "toy-uniform",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--work-dir",
            str(tmp_path),
            "--private-output",
            str(tmp_path / "result.json"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert entered_recovery
    assert captured.out == ""
    assert captured.err == ""


def test_cli_gives_production_baselines_room_to_reach_easy_instances(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed_request = None

    class Catalog:
        def get(self, _instance_id: str) -> object:
            return object()

    class CapturingSolver:
        solver_id = "primal_bdd"

        def solve(self, _instance: object, request: object) -> SolveResult:
            nonlocal observed_request
            observed_request = request
            return SolveResult.error(elapsed_seconds=0.0, work_units=0)

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(
        cli, "_resolve_solver", lambda _solver_id: CapturingSolver()
    )
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: SOLVER_REVISION)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "lwe_0066",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--work-dir",
            str(tmp_path),
            "--private-output",
            str(tmp_path / "result.json"),
        ]
    )

    assert result == 2
    assert observed_request is not None
    assert observed_request.max_seconds == 7200.0
    assert observed_request.parameters == {
        "clean_subset_cap": 1_000_000,
        "work_unit_cap": 10_000_000_000,
    }
    assert observed_request.checkpoint_every_work_units == 10_000_000


@pytest.mark.parametrize("destination_flag", ["--private-output", "--ledger"])
def test_solver_revision_mismatch_fails_before_private_setup_or_recovery(
    destination_flag: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tools.solvers import api

    solver_resolved = False
    request_constructed = False
    merge_loaded = False
    output_preflighted = False
    recovery_entered = False

    class FakeValidatedSolver(ValidatedExactSolver):
        solver_id = "primal_bdd"

        def _solve(self, instance: object, request: object) -> SolveResult:
            nonlocal recovery_entered
            recovery_entered = True
            return SolveResult.error(elapsed_seconds=0.0, work_units=0)

    class Catalog:
        def get(self, _instance_id: str) -> object:
            return object()

    def resolve_solver(_solver_id: str) -> FakeValidatedSolver:
        nonlocal solver_resolved
        solver_resolved = True
        return FakeValidatedSolver()

    def construct_request(**_kwargs: object) -> object:
        nonlocal request_constructed
        request_constructed = True
        return object()

    def load_merge_solution() -> object:
        nonlocal merge_loaded
        merge_loaded = True
        return object()

    def preflight_private_output(_path: Path, _work_dir: Path) -> None:
        nonlocal output_preflighted
        output_preflighted = True

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", resolve_solver)
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: "a" * 64)
    monkeypatch.setattr(cli, "_load_merge_solution", load_merge_solution)
    monkeypatch.setattr(cli, "_preflight_private_output", preflight_private_output)
    monkeypatch.setattr(api, "SolveRequest", construct_request)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "toy-uniform",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            "b" * 64,
            "--work-dir",
            str(tmp_path),
            destination_flag,
            str(tmp_path / "result.json"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert solver_resolved
    assert not request_constructed
    assert not merge_loaded
    assert not output_preflighted
    assert not recovery_entered
    assert captured.out == ""
    assert captured.err == "error: worker failed\n"


def test_real_canonical_registry_revision_is_enforced_by_execute(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tools.solvers.registry import require_registry_instance

    class Catalog:
        def get(self, _instance_id: str) -> object:
            return object()

    solver = cli._resolve_solver("sparse_secret_enum")
    live_revision = require_registry_instance(solver).implementation_digest
    assert cli._solver_revision(solver) == live_revision
    mismatched = "0" * 64 if live_revision != "0" * 64 else "1" * 64
    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())

    args = cli.parse_args(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "toy-uniform",
            "--solver",
            "sparse_secret_enum",
            "--expected-solver-revision",
            mismatched,
            "--work-dir",
            str(tmp_path),
            "--private-output",
            str(tmp_path / "result.json"),
        ]
    )

    with pytest.raises(ValueError, match="solver revision"):
        cli._execute(args)


def test_unsafe_private_destination_is_rejected_before_fake_solver_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    solver_called = False

    class Catalog:
        def get(self, _instance_id: str) -> object:
            return object()

    class FakeNoopSolver:
        solver_id = "primal_bdd"

        def solve(self, _instance: object, _request: object) -> SolveResult:
            nonlocal solver_called
            solver_called = True
            return SolveResult.error(elapsed_seconds=0.0, work_units=0)

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", lambda _solver_id: FakeNoopSolver())
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: SOLVER_REVISION)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "toy-uniform",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--work-dir",
            str(tmp_path / "work"),
            "--private-output",
            str(tmp_path / "outside.json"),
        ]
    )

    assert result == 2
    assert not solver_called
    assert capsys.readouterr() == ("", "error: worker failed\n")


def test_solver_import_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = "PRIVATE-IMPORT-CANARY"

    class Catalog:
        def get(self, _instance_id: str) -> object:
            return object()

    def fail_import(_solver_id: str) -> object:
        raise ModuleNotFoundError(canary)

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", fail_import)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "toy-uniform",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--work-dir",
            str(tmp_path),
            "--private-output",
            str(tmp_path / "result.json"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured == ("", "error: worker failed\n")
    assert canary not in captured.err


def test_validated_success_is_not_revalidated_after_measured_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "private-result.json"
    validation_calls = 0

    class Verdict:
        ok = True
        code = "accepted"

    class Instance:
        instance_id = "toy-uniform"

        def validate_secret(self, secret: tuple[int, ...]) -> Verdict:
            nonlocal validation_calls
            validation_calls += 1
            assert secret == (1, 0)
            return Verdict()

    instance = Instance()

    class Catalog:
        def get(self, instance_id: str) -> Instance:
            assert instance_id == instance.instance_id
            return instance

    class FakeNoopSolver(ValidatedExactSolver):
        solver_id = "primal_bdd"

        def _solve(self, observed: Instance, request: object) -> SolveResult:
            assert observed is instance
            assert request.single_worker is True
            return SolveResult.success(
                secret=(1, 0), elapsed_seconds=0.0, work_units=0
            )

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(
        cli, "_resolve_solver", lambda solver_id: FakeNoopSolver()
    )
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: SOLVER_REVISION)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "toy-uniform",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--max-seconds",
            "1",
            "--seed",
            "7",
            "--work-dir",
            str(tmp_path),
            "--private-output",
            str(output),
            "--threads",
            "1",
        ]
    )

    assert result == 0
    assert validation_calls == 1
    assert json.loads(output.read_text(encoding="ascii")) == {"secret": [1, 0]}
    assert output.read_bytes().endswith(b"\n")
    assert stat.S_IMODE(output.stat(follow_symlinks=False).st_mode) == 0o600
    assert not tuple(tmp_path.glob(".private-result.json.*.tmp"))
    assert capsys.readouterr() == ("", "")


def test_private_publication_rejects_a_swapped_temporary_inode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "private-result.json"
    real_link = cli.os.link

    def swap_then_link(
        source: object,
        destination: object,
        **kwargs: object,
    ) -> None:
        source_fd = kwargs["src_dir_fd"]
        assert type(source_fd) is int
        cli.os.unlink(source, dir_fd=source_fd)
        descriptor = cli.os.open(
            source,
            cli.os.O_WRONLY | cli.os.O_CREAT | cli.os.O_EXCL,
            0o600,
            dir_fd=source_fd,
        )
        try:
            cli.os.write(descriptor, b"attacker replacement")
        finally:
            cli.os.close(descriptor)
        real_link(source, destination, **kwargs)

    monkeypatch.setattr(cli.os, "link", swap_then_link)

    with pytest.raises(OSError, match="identity"):
        cli._atomic_write_private_output(
            output, {"secret": [987654321]}, tmp_path
        )

    assert not output.exists()
    assert not tuple(tmp_path.glob(".private-result.json.*.tmp"))


def test_private_publication_unlink_failure_removes_all_secret_names(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "private-result.json"
    real_unlink = cli.os.unlink
    failed_once = False

    def fail_first_temporary_unlink(
        path: object, *args: object, **kwargs: object
    ) -> None:
        nonlocal failed_once
        if not failed_once and str(path).endswith(".tmp"):
            failed_once = True
            raise OSError("synthetic temporary unlink failure")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(cli.os, "unlink", fail_first_temporary_unlink)

    with pytest.raises(OSError, match="temporary unlink failure"):
        cli._atomic_write_private_output(
            output, {"secret": [987654321]}, tmp_path
        )

    assert failed_once
    assert not output.exists()
    assert not tuple(tmp_path.glob(".private-result.json.*.tmp"))


def test_fake_noop_success_merges_through_top_level_ledger_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ledger = tmp_path / "solution.json"
    ledger.write_bytes(b'{"schema_version":1,"solutions":[]}\n')

    class Verdict:
        ok = True

    class Instance:
        instance_id = "private-instance"

        def validate_secret(self, secret: tuple[int, ...]) -> Verdict:
            assert secret == (987654321, -7)
            return Verdict()

    instance = Instance()

    class Catalog:
        def get(self, instance_id: str) -> Instance:
            assert instance_id == instance.instance_id
            return instance

    class FakeNoopSolver:
        solver_id = "primal_bdd"

        def solve(self, observed: Instance, request: object) -> SolveResult:
            assert observed is instance
            return SolveResult.success(
                secret=(987654321, -7), elapsed_seconds=0.0, work_units=0
            )

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", lambda _solver_id: FakeNoopSolver())
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: SOLVER_REVISION)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            instance.instance_id,
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--work-dir",
            str(tmp_path),
            "--ledger",
            str(ledger),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == (
        "solved count: 1\nsubmit new solutions immediately\n"
    )
    assert captured.err == ""
    assert "private-instance" not in captured.out
    assert "987654321" not in captured.out
    assert json.loads(ledger.read_text(encoding="utf-8"))["solutions"] == [
        {"instance_id": "private-instance", "secret": [987654321, -7]}
    ]


def test_ledger_boundary_is_pinned_before_solver_and_ignores_module_poisoning(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ledger = tmp_path / "solution.json"
    ledger.write_bytes(b'{"schema_version":1,"solutions":[]}\n')
    leaked: list[tuple[int, ...]] = []
    poison = ModuleType("add_solution")

    def poison_merge(
        _path: Path, _instance_id: str, secret: tuple[int, ...]
    ) -> int:
        leaked.append(tuple(secret))
        return 99

    poison.merge_solution = poison_merge
    monkeypatch.setitem(sys.modules, "add_solution", poison)
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "add_solution.py").write_text(
        "raise RuntimeError('PRIVATE-SHADOW-CANARY')\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(shadow)

    class Verdict:
        ok = True

    class Instance:
        instance_id = "private-instance"

        def validate_secret(self, _secret: tuple[int, ...]) -> Verdict:
            return Verdict()

    instance = Instance()

    class Catalog:
        def get(self, _instance_id: str) -> Instance:
            return instance

    class FakeNoopSolver:
        solver_id = "primal_bdd"

        def solve(self, _instance: Instance, _request: object) -> SolveResult:
            return SolveResult.success(
                secret=(7, -3), elapsed_seconds=0.0, work_units=0
            )

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", lambda _solver_id: FakeNoopSolver())
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: SOLVER_REVISION)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            instance.instance_id,
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--work-dir",
            str(tmp_path),
            "--ledger",
            str(ledger),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert leaked == []
    assert captured == (
        "solved count: 1\nsubmit new solutions immediately\n",
        "",
    )
    assert json.loads(ledger.read_text(encoding="utf-8"))["solutions"] == [
        {"instance_id": "private-instance", "secret": [7, -3]}
    ]


def test_fake_noop_censoring_writes_closed_private_protocol(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "private-result.json"

    class Catalog:
        def get(self, _instance_id: str) -> object:
            return object()

    class FakeNoopSolver:
        solver_id = "primal_bdd"

        def solve(self, _instance: object, _request: object) -> SolveResult:
            return SolveResult.censored(
                elapsed_seconds=0.0,
                work_units=0,
                detail={"code": "time_cap"},
            )

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", lambda _solver_id: FakeNoopSolver())
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: SOLVER_REVISION)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "toy-uniform",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--max-seconds",
            "17",
            "--work-dir",
            str(tmp_path),
            "--private-output",
            str(output),
        ]
    )

    assert result == 0
    payload = json.loads(output.read_text(encoding="ascii"))
    assert payload == {
        "censor_cap": 17.0,
        "censor_unit": "seconds",
        "reason": "wall_cap",
        "status": "CENSORED",
    }
    assert capsys.readouterr() == ("", "")


def test_non_wall_censoring_is_not_misreported_as_a_wall_cap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "private-result.json"

    class Catalog:
        def get(self, _instance_id: str) -> object:
            return object()

    class FakeNoopSolver:
        solver_id = "primal_bdd"

        def solve(self, _instance: object, _request: object) -> SolveResult:
            return SolveResult.censored(
                elapsed_seconds=0.0,
                work_units=0,
                detail={"code": "work_unit_cap"},
            )

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", lambda _solver_id: FakeNoopSolver())
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: SOLVER_REVISION)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            "toy-uniform",
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--work-dir",
            str(tmp_path),
            "--private-output",
            str(output),
        ]
    )

    assert result == 2
    assert not output.exists()
    assert capsys.readouterr() == ("", "error: worker failed\n")


def test_fake_noop_exhaustion_writes_publicly_replayable_certificate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "private-result.json"

    class Instance:
        instance_id = "toy-uniform"
        instance_digest = "b" * 64
        n = 2
        q = 3
        secret_predicate_kind = "alphabet"
        secret_alphabet = (-1, 0, 1)
        secret_min_nonzero = 0
        secret_max_nonzero = 2

    instance = Instance()

    class Catalog:
        def get(self, _instance_id: str) -> Instance:
            return instance

    class FakeNoopSolver:
        solver_id = "primal_bdd"

        def solve(self, _instance: Instance, _request: object) -> SolveResult:
            return SolveResult.exhausted(
                elapsed_seconds=0.0,
                work_units=9,
                detail={
                    "certificate_id": "complete_public_domain_v1",
                    "certificate_digest": "c" * 64,
                    "public_parameters": {
                        "domain_size": 9,
                        "range_start": 0,
                        "range_stop": 9,
                    },
                },
            )

    monkeypatch.setattr(cli, "load_catalog", lambda _args: Catalog())
    monkeypatch.setattr(cli, "_resolve_solver", lambda _solver_id: FakeNoopSolver())
    monkeypatch.setattr(cli, "_solver_revision", lambda _solver: "a" * 64)

    result = cli.main(
        [
            "--catalog",
            "unused.json",
            "--instance",
            instance.instance_id,
            "--solver",
            "primal_bdd",
            "--expected-solver-revision",
            SOLVER_REVISION,
            "--seed",
            "7",
            "--work-dir",
            str(tmp_path),
            "--private-output",
            str(output),
        ]
    )

    assert result == 0
    payload = json.loads(output.read_text(encoding="ascii"))
    certificate = payload["certificate"]
    assert payload["status"] == "EXHAUSTED"
    unsigned = {
        key: value
        for key, value in certificate.items()
        if key != "certificate_digest"
    }
    encoded = (
        json.dumps(
            unsigned,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    assert certificate == {
        **unsigned,
        "certificate_digest": hashlib.sha256(encoded).hexdigest(),
    }
    assert unsigned == {
        "certificate_id": "complete_public_domain_v1",
        "certificate_version": 1,
        "instance_id": "toy-uniform",
        "instance_digest": "b" * 64,
        "solver_id": "primal_bdd",
        "solver_revision": "a" * 64,
        "solver_seed": 7,
        "domain_size": 9,
        "range_start": 0,
        "range_stop": 9,
    }
