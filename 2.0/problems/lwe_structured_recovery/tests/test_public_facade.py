import hashlib

import pytest

import lwe_instance


_INSTANCE_PROPERTIES = {
    "instance_id",
    "n",
    "m",
    "q",
    "b",
    "family",
    "tier",
    "cohort",
    "runtime_bin",
    "octave",
    "matrix_kind",
    "matrix_seed_hex",
    "matrix_expansion_domain",
    "matrix_alphabet",
    "matrix_row_weight",
    "secret_distribution_kind",
    "secret_predicate_kind",
    "secret_alphabet",
    "secret_weight",
    "secret_eta",
    "secret_min_nonzero",
    "secret_max_nonzero",
    "error_distribution_kind",
    "error_sigma",
    "error_eta",
    "error_bound",
    "error_weight",
    "error_max_abs",
    "error_max_l1",
    "error_max_l2_squared",
    "error_max_nonzero",
    "analysis_path",
    "generator_version",
    "calibration_status",
    "calibration_model_id",
    "predicted_runtime_seconds",
    "measured_runtime_seconds",
    "instance_digest",
}
_INSTANCE_METHODS = {
    "iter_rows",
    "materialize_row_block",
    "materialize_rows",
    "matvec",
    "validate_secret",
}


def test_public_facade_supports_phase3_solver_workflow(catalog_path) -> None:
    catalog = lwe_instance.Catalog.load(catalog_path)
    instance = catalog.get("toy-uniform")

    assert instance.instance_id == "toy-uniform"
    assert len(instance.b) == instance.m
    assert instance.family == "MIX_DENSE_SMALL"
    assert instance.matrix_kind == "uniform"
    assert instance.secret_distribution_kind == "iid_alphabet"
    assert instance.secret_predicate_kind == "alphabet"
    assert tuple(instance.iter_rows()) == instance.materialize_rows()
    assert instance.materialize_row_block(1, 3) == instance.materialize_rows()[1:3]
    assert len(instance.materialize_rows()) == instance.m
    assert len(instance.matvec((0,) * instance.n)) == instance.m
    assert instance.validate_secret((0,) * instance.n).code in {
        "ok",
        "secret_weight",
        "error_linf",
        "error_l1",
        "error_l2",
        "error_weight",
    }


def test_public_facade_has_exact_supported_surface_and_primitive_values(
    catalog_path,
) -> None:
    assert set(lwe_instance.__all__) == {"Catalog", "Instance", "WitnessVerdict"}
    assert {
        name for name in vars(lwe_instance) if not name.startswith("_")
    } == {"Catalog", "Instance", "WitnessVerdict"}

    instance = lwe_instance.Catalog.load(catalog_path).get("toy-sparse")
    assert {
        name for name in dir(instance) if not name.startswith("_")
    } == _INSTANCE_PROPERTIES | _INSTANCE_METHODS
    assert {name: getattr(instance, name) for name in _INSTANCE_PROPERTIES} == {
        "instance_id": "toy-sparse",
        "n": 4,
        "m": 3,
        "q": 19,
        "b": (5, 6, 7),
        "family": "MIX_SMALL_SPARSE",
        "tier": "synthetic",
        "cohort": "synthetic",
        "runtime_bin": "synthetic",
        "octave": None,
        "matrix_kind": "sparse_small_alphabet",
        "matrix_seed_hex": "11" * 32,
        "matrix_expansion_domain": "FCS-STRUCTURED-LWE-MATRIX-v1",
        "matrix_alphabet": (-1, 1),
        "matrix_row_weight": 2,
        "secret_distribution_kind": "exact_weight_alphabet",
        "secret_predicate_kind": "alphabet",
        "secret_alphabet": (-1, 0, 1),
        "secret_weight": 2,
        "secret_eta": None,
        "secret_min_nonzero": 2,
        "secret_max_nonzero": 2,
        "error_distribution_kind": "sparse_bounded",
        "error_sigma": None,
        "error_eta": None,
        "error_bound": 1,
        "error_weight": 1,
        "error_max_abs": 1,
        "error_max_l1": 1,
        "error_max_l2_squared": 1,
        "error_max_nonzero": 1,
        "analysis_path": "analysis/toy-sparse.md",
        "generator_version": "synthetic-fixture-v1",
        "calibration_status": "unmeasured",
        "calibration_model_id": "",
        "predicted_runtime_seconds": 0.0,
        "measured_runtime_seconds": None,
        "instance_digest": (
            "8a3d59c201a9b6a117f12a7a91067a668650fa4de10a013db900b8f99e612874"
        ),
    }


def test_catalog_preserves_order_identity_and_lookup_contract(catalog_path) -> None:
    catalog = lwe_instance.Catalog.load(str(catalog_path))

    assert {
        name for name in dir(catalog) if not name.startswith("_")
    } == {"catalog_id", "get", "instances", "load"}
    assert catalog.catalog_id == hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    assert tuple(instance.instance_id for instance in catalog.instances) == (
        "toy-uniform",
        "toy-sparse",
    )
    assert catalog.get("toy-uniform") is catalog.instances[0]
    assert catalog.get("toy-uniform") is catalog.get("toy-uniform")

    with pytest.raises(KeyError) as missing:
        catalog.get("not-present")
    assert missing.value.args == ("not-present",)


def test_facade_objects_are_read_only_and_repr_hides_wrapped_schema(
    catalog_path,
) -> None:
    catalog = lwe_instance.Catalog.load(catalog_path)
    instance = catalog.instances[0]
    verdict = instance.validate_secret((0,) * instance.n)

    assert type(verdict) is lwe_instance.WitnessVerdict
    assert "InstanceSpec" not in repr(instance)
    assert "lwe_challenge" not in repr(instance)
    assert str(catalog_path) not in repr(catalog)
    assert not hasattr(instance, "__dict__")
    assert not hasattr(catalog, "__dict__")

    with pytest.raises(AttributeError):
        instance.n = 99
    with pytest.raises(AttributeError):
        catalog.instances = ()
    with pytest.raises(AttributeError):
        instance._Instance__spec = None
    with pytest.raises(AttributeError):
        catalog._Catalog__instances = ()
    with pytest.raises(TypeError):
        catalog._Catalog__instances_by_id["new"] = instance
    with pytest.raises(AttributeError):
        verdict.code = "changed"


def test_instance_methods_match_published_matrix_and_witness_expectations(
    catalog_path,
) -> None:
    instance = lwe_instance.Catalog.load(catalog_path).get("toy-uniform")
    expected_rows = (
        (16, 12, 0),
        (2, 8, 7),
        (8, 6, 10),
        (14, 2, 3),
    )
    secret = (1, 0, -1)

    assert tuple(instance.iter_rows()) == expected_rows
    assert instance.materialize_rows() == expected_rows
    assert instance.materialize_row_block(1, 3) == expected_rows[1:3]
    assert instance.matvec(secret) == (16, 12, 15, 11)
    assert instance.validate_secret(secret) == lwe_instance.WitnessVerdict(
        True,
        "ok",
        1,
        3,
        3,
    )
    assert instance.validate_secret((0,)).code == "wrong_length"

    with pytest.raises(ValueError, match="row block bounds"):
        instance.materialize_row_block(3, 2)
    with pytest.raises(ValueError, match="secret length"):
        instance.matvec((0,))
