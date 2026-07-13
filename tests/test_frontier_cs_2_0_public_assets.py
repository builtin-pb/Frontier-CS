from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_SRC = REPO_ROOT / "adapters" / "frontier-cs-2.0" / "src"
sys.path.insert(0, str(ADAPTER_SRC))

import frontier_cs_2_0.adapter as adapter_module
from frontier_cs_2_0.adapter import FrontierCS20Adapter


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


def test_whole_app_staging_preserves_nonpublic_symlinks(tmp_path: Path) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    outside = tmp_path / "outside-tool.py"
    outside.write_text("must not be dereferenced during staging\n", encoding="utf-8")
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

    assert staged_link.is_symlink()
    assert staged_link.readlink() == outside


def test_staged_public_tree_is_revalidated_before_judge_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    outside = tmp_path / "outside-after-validation"
    outside.write_text("must not enter the staged public tree", encoding="utf-8")
    real_copytree = adapter_module.shutil.copytree
    source_app = repo / "2.0/problems/json_fixture/harbor/app"

    def copytree_with_staged_symlink(*args: object, **kwargs: object) -> Path:
        result = real_copytree(*args, **kwargs)
        if Path(args[0]) != source_app:
            return result
        staged_catalog = Path(args[1]) / "public/catalog.jsonl"
        staged_catalog.unlink()
        staged_catalog.symlink_to(outside)
        return result

    monkeypatch.setattr(adapter_module.shutil, "copytree", copytree_with_staged_symlink)

    with pytest.raises(ValueError, match="public assets may not contain symlinks"):
        FrontierCS20Adapter(
            repo,
            tmp_path / "generated",
            task_ids=["json_fixture"],
        ).run()


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
