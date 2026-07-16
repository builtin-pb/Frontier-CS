from pathlib import Path
import sys
import tomllib

import yaml

from frontier_cs.config import get_problem_extension


def _load_frontier_cs_20_adapter(root: Path):
    adapter_src = root / "adapters" / "frontier-cs-2.0" / "src"
    sys.path.insert(0, str(adapter_src))
    try:
        from frontier_cs_2_0.adapter import FrontierCS20Adapter
    finally:
        assert sys.path.pop(0) == str(adapter_src)
    return FrontierCS20Adapter


def test_lwe_structured_recovery_uses_json_reference() -> None:
    root = Path(__file__).parents[1]
    task = root / "2.0/problems/lwe_structured_recovery"
    assert get_problem_extension(task) == "json"
    assert (task / "reference.json").read_text(encoding="utf-8") == (
        '{"schema_version":1,"solutions":[]}\n'
    )


def test_lwe_structured_recovery_readme_publishes_complete_agent_contract() -> None:
    root = Path(__file__).parents[1]
    task = root / "2.0/problems/lwe_structured_recovery"
    config = yaml.safe_load(
        (task / "config.yaml").read_text(encoding="utf-8")
    )
    readme_raw = (task / "readme").read_text(encoding="utf-8")
    readme = " ".join(readme_raw.split())
    paths = readme_raw.split(
        "## Public catalog and stable Python interface", 1
    )[1].split("##", 1)[0]

    required_fragments = (
        "/app/solution.json",
        "bash /app/submit.sh",
        "/app/public/catalog.jsonl",
        "/app/LITERATURE.md",
        "/app/analyses/",
        "/app/tools/solvers/",
        "public/lwe_instance.py",
        "from lwe_instance import Catalog",
        '"schema_version": 1',
        '"solutions"',
        '"instance_id"',
        '"secret"',
        "center_q(b_i - (A s)_i)",
        "error_max_abs",
        "error_max_l1",
        "error_max_l2_squared",
        "error_max_nonzero",
        "score = 100 * solved_count / instance_count",
        "score_unbounded = solved_count",
        "python3 /app/add_solution.py",
        "2,000,000 bytes",
        "at most 4 levels of JSON nesting",
        "820,205 decoded nodes",
        "a nested secret such as `[[0]]` is rejected before per-record validation",
        "zero even when another record is valid",
        "length is at most 4,096",
        "production catalog contains exactly 200 instances",
        "canonical empty ledger is pre-provisioned at /app/solution.json",
        "identical existing witness is an idempotent no-op",
        "different existing witness is rejected unless you pass --replace",
        "every repeated safe instance_id invalidates every occurrence",
        "safe means syntactically valid under the instance-ID regex",
        "duplicate_count counts distinct syntactically valid IDs",
        "conflict_count counts distinct IDs",
        "within the ledger integer bound and at most 4,096 components",
        "syntactically valid but unknown instance_id is a per-record",
        "unknown_instance_id",
        "does not invalidate the whole ledger",
        "unknown_count counts distinct regex-valid IDs absent from the catalog",
        "even when an ID is repeated or another field in its record is malformed",
        (
            "unknown_instance_id applies only to a unique otherwise "
            "syntactically admissible record"
        ),
        "invalid_record_fields takes precedence for a unique malformed unknown",
        "invalid_secret takes precedence for a unique malformed unknown",
        (
            "duplicate_instance_id takes precedence for every occurrence "
            "of a repeated ID"
        ),
        "violating a whole-file rule scores zero",
        "per-record rejection does not invalidate the whole ledger",
        (
            "successful add_solution exit and write enforces canonical "
            "structural ledger rules"
        ),
        "does not prove catalog membership or mathematical witness validity",
        (
            "refuses an update that would exceed the 200-record or "
            "2,000,000-byte cap"
        ),
        "validate_secret checks mathematical witness validity",
        "ledger admissibility is a separate check",
        "secret_alphabet is the acceptance alphabet",
        (
            "`exact_weight_alphabet` generation alphabet is "
            "`secret_alphabet` with zero removed"
        ),
        (
            "`balanced_exact_weight_signed` plant specifically uses "
            "`{-1,1}` on its support"
        ),
        (
            "`iid_alphabet` and `centered_binomial` generation and "
            "acceptance alphabets coincide"
        ),
        "Ubuntu 24.04",
        "Python 3.12",
        "public feedback",
        "solved_ids",
        "rejection_code_counts",
        "evaluator holds no secret",
        "submit after every newly validated secret for a previously unsolved instance",
        "score-changing replacement",
        "retain all prior entries",
        (
            "`bash /app/submit.sh` snapshots and queues the current "
            "`/app/solution.json`"
        ),
        "prints a submission UUID",
        "bash /app/wait_submission.sh SUBMISSION_UUID",
        "bash /app/submissions.sh",
        "`wait_submission.sh` prints the completed score, message, and metrics",
        "Add `--json` to either wait or list",
        "complete structured submission record",
    )
    missing = [
        fragment for fragment in required_fragments if fragment not in readme
    ]
    assert not missing, (
        f"readme is missing agent-contract fragments: {missing}"
    )

    resources = config["environment"]
    runtime = config["runtime"]
    expected_config_fragments = (
        f"{resources['cpus']} CPU cores",
        f"{resources['memory_mb'] // 1024} GiB memory",
        f"{resources['storage_mb'] // 1024} GiB storage",
        (
            f"{runtime['timeout_seconds']:,} seconds "
            f"({runtime['timeout_seconds'] // 3600} hours)"
        ),
        (
            f"{resources['build_timeout_seconds']:,} seconds "
            f"({resources['build_timeout_seconds'] // 60} minutes)"
        ),
        *runtime["pip_packages"],
    )
    missing_config = [
        fragment
        for fragment in expected_config_fragments
        if fragment not in readme
    ]
    assert not missing_config, (
        f"readme is stale against config.yaml: {missing_config}"
    )
    assert "fplll-tools" in runtime["apt_packages"]
    assert "fplll-tools" in readme
    assert (
        f"at most {config['submission']['max_queue_size']} pending submissions"
        in readme
    )
    assert "/app/submit.sh" in paths
    assert "Python 3.11" not in readme


def test_lwe_structured_recovery_runtime_description_matches_image() -> None:
    root = Path(__file__).parents[1]
    task = root / "2.0/problems/lwe_structured_recovery"
    config = yaml.safe_load(
        (task / "config.yaml").read_text(encoding="utf-8")
    )

    assert config["runtime"]["docker"]["image"] == "ubuntu:24.04"
    assert config["runtime"]["environment"] == (
        "Public structured-LWE instances; Python 3.12 helper library; "
        "CPU only"
    )


def test_lwe_structured_recovery_generates_complete_harbor_package(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    adapter = _load_frontier_cs_20_adapter(root)
    generated = adapter(
        root,
        tmp_path / "generated",
        task_ids=["lwe_structured_recovery"],
    ).run()

    assert len(generated) == 1
    task = generated[0]
    source_app = root / "2.0/problems/lwe_structured_recovery/harbor/app"
    packaged_app = task / "environment" / "harbor_app"
    task_config = tomllib.loads(
        task.joinpath("task.toml").read_text(encoding="utf-8")
    )
    assert "security" in task_config["task"]["keywords"]
    for relative in (
        Path("public/catalog.jsonl"),
        Path("public/catalog.sha256"),
        Path("LITERATURE.md"),
        Path("solution.json"),
    ):
        assert packaged_app.joinpath(relative).read_bytes() == (
            source_app.joinpath(relative).read_bytes()
        )
    assert len(list(packaged_app.joinpath("analyses").glob("lwe_*.md"))) == 200
    assert len(list(packaged_app.joinpath("public/specs").glob("lwe_*.json"))) == 200
    judge = task.joinpath("environment/Dockerfile.judge").read_text(
        encoding="utf-8"
    )
    assert "COPY harbor_app/public/ /judge/public/" in judge
    assert "ENV FRONTIER_PUBLIC_DIR=/judge/public" in judge
    assert "COPY harbor_app/ /judge/" not in judge
    assert not any(path.name == "__pycache__" for path in packaged_app.rglob("*"))
    assert not any(
        path.suffix in {".pyc", ".pyo"} for path in packaged_app.rglob("*")
    )
