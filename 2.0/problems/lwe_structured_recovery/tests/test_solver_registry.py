from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.solvers.api import ValidatedExactSolver
from tools.solvers.registry import (
    FAMILIES,
    RegistryError,
    canonical_solver_implementation_receipt,
    instantiate_solver,
    load_registry,
    load_sources,
    require_registry_instance,
    resolve_applicability,
)


EXPECTED_SOLVERS = (
    "primal_bdd",
    "sparse_secret_enum",
    "sparse_secret_mitm",
    "small_secret_hybrid",
    "repeated_support",
    "graph_peeling",
    "dense_minor",
    "mixed_filter_greedy",
    "support_incidence",
    "bounded_error",
)
TASK_DIR = Path(__file__).parents[1]
SOLVER_DIR = TASK_DIR / "maintainer" / "tools" / "solvers"


def test_registry_has_the_public_reference_portfolio() -> None:
    records = load_registry()
    assert tuple(record.solver_id for record in records) == EXPECTED_SOLVERS
    assert len({record.entrypoint for record in records}) == len(records)
    assert all(record.task == "exact_search" for record in records)
    assert all(record.families and set(record.families) <= FAMILIES for record in records)


def test_every_registered_solver_is_lazy_importable_and_uses_common_wrapper() -> None:
    for record in load_registry():
        solver = instantiate_solver(record)
        assert isinstance(solver, ValidatedExactSolver)
        assert type(solver).solve is ValidatedExactSolver.solve
        assert solver.solver_id == record.solver_id
        assert callable(resolve_applicability(record))


def test_implementation_receipts_are_stable_public_source_digests() -> None:
    for record in load_registry():
        first = canonical_solver_implementation_receipt(record)
        second = require_registry_instance(instantiate_solver(record))
        assert first == second
        assert first.solver_id == record.solver_id
        assert len(first.implementation_digest) == 64
        assert first.source_files
        assert all(path.startswith("tools/solvers/") for path, _ in first.source_files)


def _receipt_with_mutated_source(
    monkeypatch: pytest.MonkeyPatch,
    *,
    solver_id: str,
    source_name: str,
):
    record = next(record for record in load_registry() if record.solver_id == solver_id)
    original = canonical_solver_implementation_receipt(record)
    source_path = (SOLVER_DIR / source_name).resolve()
    read_bytes = Path.read_bytes

    def mutate_selected_source(path: Path) -> bytes:
        payload = read_bytes(path)
        if path.resolve() == source_path:
            return payload + b"\n# implementation revision probe\n"
        return payload

    monkeypatch.setattr(Path, "read_bytes", mutate_selected_source)
    mutated = canonical_solver_implementation_receipt(record)
    return original, mutated


def test_implementation_receipt_binds_the_shared_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original, mutated = _receipt_with_mutated_source(
        monkeypatch,
        solver_id="primal_bdd",
        source_name="api.py",
    )
    assert "tools/solvers/api.py" in dict(original.source_files)
    assert mutated.implementation_digest != original.implementation_digest


def test_implementation_receipt_binds_the_solver_package_initializer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original, mutated = _receipt_with_mutated_source(
        monkeypatch,
        solver_id="primal_bdd",
        source_name="__init__.py",
    )
    assert "tools/solvers/__init__.py" in dict(original.source_files)
    assert mutated.implementation_digest != original.implementation_digest


@pytest.mark.parametrize(
    ("solver_id", "source_name"),
    (
        ("small_secret_hybrid", "primal_bdd.py"),
        ("mixed_filter_greedy", "sparse_matrix.py"),
        ("support_incidence", "support_incidence.py"),
    ),
)
def test_implementation_receipt_binds_nested_and_shared_solver_modules(
    monkeypatch: pytest.MonkeyPatch,
    solver_id: str,
    source_name: str,
) -> None:
    original, mutated = _receipt_with_mutated_source(
        monkeypatch,
        solver_id=solver_id,
        source_name=source_name,
    )
    assert f"tools/solvers/{source_name}" in dict(original.source_files)
    assert mutated.implementation_digest != original.implementation_digest


def test_sources_cover_every_declared_method_and_context() -> None:
    sources = load_sources()
    assert sources
    cited = {
        source_id
        for record in load_registry()
        for source_id in (*record.method_sources, *record.context_sources)
    }
    assert cited <= set(sources)
    assert all(source.versioned_url.startswith("https://") for source in sources.values())


def test_source_roles_cover_literature_route_guardrails_and_estimator() -> None:
    sources = load_sources()
    assert sources["sun-tibouchi-abe-2020"].source_role == "literature_route"
    assert sources["son-cheon-2019"].source_role == "literature_route"
    assert sources["brakerski-dottling-2020"].source_role == "parameter_guardrail"
    assert (
        sources["bangachev-bresler-tiegel-vaikuntanathan-2024"].source_role
        == "parameter_guardrail"
    )
    assert sources["malb-lattice-estimator-3e48ef4"].source_role == "estimation_tool"
    assert (
        sources["albrecht-curtis-et-al-2018"].source_role
        == "estimation_methodology"
    )
    for source_id in (
        "albrecht-goepfert-virdia-wunderer-2017",
        "espitau-joux-kharchenko-2020",
        "arora-ge-2011",
        "steiner-2024",
    ):
        assert sources[source_id].source_role == "analysis_context"

    bounded_error = next(
        record for record in load_registry() if record.solver_id == "bounded_error"
    )
    assert bounded_error.origin == "paper_method"
    assert bounded_error.method_sources == ("sun-tibouchi-abe-2020",)
    assert bounded_error.context_sources == ("arora-ge-2011", "steiner-2024")
    assert bounded_error.paper_case_eligible

    sparse_enum = next(
        record for record in load_registry() if record.solver_id == "sparse_secret_enum"
    )
    assert sparse_enum.origin == "paper_method"
    assert sparse_enum.method_sources == ("son-cheon-2019",)
    assert sparse_enum.context_sources == ()
    assert sparse_enum.paper_case_eligible


def test_paper_case_labels_require_a_method_source() -> None:
    for record in load_registry():
        if record.paper_case_eligible:
            assert record.origin == "paper_method"
            assert record.method_sources


def test_registry_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_text('{"schema_version":1,"schema_version":1,"solvers":[]}', encoding="utf-8")
    with pytest.raises(RegistryError, match="duplicate JSON key"):
        load_registry(path)


def test_registry_rejects_unknown_sources(tmp_path: Path) -> None:
    raw = json.loads(
        (SOLVER_DIR / "registry.json").read_text(encoding="utf-8")
    )
    raw["solvers"][0]["method_sources"] = ["missing-source"]
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(RegistryError, match="unknown source"):
        load_registry(path)


def test_registry_resources_contain_no_private_witness_material(task_dir: Path) -> None:
    payload = b"".join(
        (task_dir / relative).read_bytes()
        for relative in (
            "maintainer/tools/solvers/registry.json",
            "maintainer/tools/solvers/sources.json",
            "maintainer/tools/solvers/THIRD_PARTY_NOTICES.md",
        )
    ).lower()
    for forbidden in (
        b"private_seed",
        b"private_secret",
        b"private_error",
        b"planted_secret",
        b"answer_hash",
    ):
        assert forbidden not in payload


def test_public_solver_fixture_roster_uses_only_the_public_facade(solver_catalog) -> None:
    assert tuple(instance.instance_id for instance in solver_catalog.instances) == (
        "binary_fixture",
        "repeated_support_fixture",
        "graph_peeling_fixture",
        "dense_minor_fixture",
        "mixed_fixture",
        "sparse_error_fixture",
        "primal_fixture",
        "hybrid_fixture",
        "unique_fixture",
        "multiple_witness_fixture",
    )
    for instance in solver_catalog.instances:
        assert not instance.validate_secret((0,) * instance.n).ok
        assert not instance.validate_secret((1,) * instance.n).ok
        assert not instance.validate_secret((instance.q - 1,) * instance.n).ok
