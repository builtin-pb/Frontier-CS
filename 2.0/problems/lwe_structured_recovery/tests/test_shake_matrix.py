import ast
import hashlib
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from lwe_challenge.matrix import (
    iter_rows,
    materialize_row_block,
    materialize_rows,
    matvec_mod,
)
from lwe_challenge.schema import Catalog, InstanceSpec, MatrixSpec
from lwe_challenge.shake import ShakeStream


_EXPECTED_ROWS = {
    "uniform": (
        (16, 12, 0),
        (2, 8, 7),
        (8, 6, 10),
        (14, 2, 3),
    ),
    "small_alphabet": (
        (0, -2, -2),
        (0, -2, 0),
        (3, -2, 3),
        (3, 0, 0),
    ),
    "sparse_uniform": (
        (0, 1, 12),
        (13, 16, 0),
        (12, 0, 4),
        (6, 0, 15),
    ),
    "sparse_small_alphabet": (
        (0, 1, 0, -1),
        (0, -1, 0, -1),
        (1, 0, 1, 0),
    ),
}

# Both row-zero streams use an upper bound of 129. Their first raw bytes are
# 0xa2 and 0xa1 (rejected), followed by 0x6c and 0x18 (accepted), respectively.
_REJECTION_HEAVY_EXPECTED_ROWS = {
    "uniform": (
        (108, 11, 47),
        (68, 75, 92),
        (103, 44, 47),
        (88, 38, 88),
    ),
    "small_alphabet": (
        (-40, -26, 41),
        (11, -22, -27),
        (16, -22, 33),
        (-52, -5, -1),
    ),
}

_UINT32_MAX_EXPECTED_ROWS = {
    "uniform": (
        (2377131788, 449018136, 3194565496),
        (3814720769, 3790477421, 1230977265),
        (1343482665, 2710448934, 3209516515),
    ),
    "saturated_sparse": (
        (3569788618, 355618608, 1703893593),
        (3735900604, 3112700878, 4069098076),
        (2468320637, 1667465268, 1395104943),
    ),
}

_TASK_DIR = Path(__file__).resolve().parents[1]
_MATRIX_REF_SOURCE = _TASK_DIR / "maintainer" / "tools" / "audit" / "matrix_ref.c"
_COMPILE_TIMEOUT_SECONDS = 30
_NATIVE_TIMEOUT_SECONDS = 10


@pytest.fixture(scope="module")
def matrix_ref_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    binary = tmp_path_factory.mktemp("matrix-ref") / "matrix_ref"
    completed = subprocess.run(
        [
            "cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(_MATRIX_REF_SOURCE),
            "-o",
            str(binary),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=_COMPILE_TIMEOUT_SECONDS,
    )
    assert completed.returncode == 0, completed.stderr
    return binary


def _native_argv(
    binary: Path,
    instance: InstanceSpec,
    *,
    start: int,
    stop: int,
) -> list[str]:
    arguments = [
        str(binary),
        "--seed",
        instance.matrix.seed_hex,
        "--domain",
        instance.matrix.expansion_domain,
        "--instance-id",
        instance.instance_id,
        "--n",
        str(instance.n),
        "--q",
        str(instance.q),
        "--kind",
        instance.matrix.kind,
    ]
    if instance.matrix.kind in {"small_alphabet", "sparse_small_alphabet"}:
        arguments.extend(
            ["--alphabet", ",".join(map(str, instance.matrix.alphabet))]
        )
    if instance.matrix.kind in {"sparse_uniform", "sparse_small_alphabet"}:
        assert instance.matrix.row_weight is not None
        arguments.extend(["--row-weight", str(instance.matrix.row_weight)])
    arguments.extend(["--start", str(start), "--stop", str(stop)])
    return arguments


def _native_rows(
    binary: Path,
    instance: InstanceSpec,
    *,
    start: int,
    stop: int,
) -> tuple[tuple[int, ...], ...]:
    completed = subprocess.run(
        _native_argv(binary, instance, start=start, stop=stop),
        check=True,
        capture_output=True,
        text=True,
        timeout=_NATIVE_TIMEOUT_SECONDS,
    )
    assert completed.stderr == ""
    return tuple(
        tuple(int(value) for value in line.split())
        for line in completed.stdout.splitlines()
    )


def _small_alphabet_instance(catalog: Catalog) -> InstanceSpec:
    base = catalog.get("toy-uniform")
    return replace(
        base,
        instance_id="toy-small-alphabet",
        matrix=MatrixSpec(
            kind="small_alphabet",
            seed_hex="22" * 32,
            expansion_domain=base.matrix.expansion_domain,
            alphabet=(-2, 0, 3),
            row_weight=None,
        ),
    )


def _sparse_uniform_instance(catalog: Catalog) -> InstanceSpec:
    base = catalog.get("toy-uniform")
    return replace(
        base,
        instance_id="toy-sparse-uniform",
        matrix=MatrixSpec(
            kind="sparse_uniform",
            seed_hex="33" * 32,
            expansion_domain=base.matrix.expansion_domain,
            alphabet=(),
            row_weight=2,
        ),
    )


def _instance_for_kind(catalog: Catalog, kind: str) -> InstanceSpec:
    if kind == "uniform":
        return catalog.get("toy-uniform")
    if kind == "small_alphabet":
        return _small_alphabet_instance(catalog)
    if kind == "sparse_uniform":
        return _sparse_uniform_instance(catalog)
    if kind == "sparse_small_alphabet":
        return catalog.get("toy-sparse")
    raise AssertionError(f"unhandled test matrix kind: {kind}")


def _rejection_heavy_instance(catalog: Catalog, kind: str) -> InstanceSpec:
    base = catalog.get("toy-uniform")
    if kind == "uniform":
        return replace(
            base,
            instance_id="toy-heavy-uniform",
            q=129,
            matrix=MatrixSpec(
                kind="uniform",
                seed_hex="00" * 32,
                expansion_domain=base.matrix.expansion_domain,
                alphabet=(),
                row_weight=None,
            ),
        )
    if kind == "small_alphabet":
        return replace(
            base,
            instance_id="toy-heavy-alphabet",
            q=257,
            matrix=MatrixSpec(
                kind="small_alphabet",
                seed_hex="01" * 32,
                expansion_domain=base.matrix.expansion_domain,
                alphabet=tuple(range(-64, 65)),
                row_weight=None,
            ),
        )
    raise AssertionError(f"unhandled rejection-heavy matrix kind: {kind}")


def _uint32_boundary_instance(catalog: Catalog, case: str) -> InstanceSpec:
    base = catalog.get("toy-uniform")
    if case == "uniform":
        return replace(
            base,
            instance_id="toy-qmax-uniform",
            q=2**32 - 1,
            matrix=MatrixSpec(
                kind="uniform",
                seed_hex="66" * 32,
                expansion_domain=base.matrix.expansion_domain,
                alphabet=(),
                row_weight=None,
            ),
        )
    if case == "saturated_sparse":
        return replace(
            base,
            instance_id="toy-qmax-saturated-sparse",
            q=2**32 - 1,
            matrix=MatrixSpec(
                kind="sparse_uniform",
                seed_hex="77" * 32,
                expansion_domain=base.matrix.expansion_domain,
                alphabet=(),
                row_weight=base.n,
            ),
        )
    raise AssertionError(f"unhandled uint32 boundary case: {case}")


def test_shake_stream_has_stable_first_block() -> None:
    stream = ShakeStream(domain=b"FCS-STRUCTURED-LWE-TEST-v1", seed=bytes(32))
    assert stream.read(16).hex() == "27027578f05e9bd4933317218e161c7e"


def test_shake_stream_buffers_across_blocks_without_advancing_on_zero_read() -> None:
    domain = b"buffer-test"
    seed = bytes.fromhex("ab" * 32)
    expected = b"".join(
        hashlib.shake_256(
            domain + b"\0" + seed + index.to_bytes(8, "little")
        ).digest(64)
        for index in range(2)
    )[:80]
    stream = ShakeStream(domain=domain, seed=seed)

    assert stream.read(0) == b""
    assert stream.read(7) + stream.read(73) == expected


@pytest.mark.parametrize(
    ("domain", "seed"),
    [
        (b"", bytes(32)),
        ("domain", bytes(32)),
        (b"domain", b"short"),
        (b"domain", "0" * 32),
    ],
)
def test_shake_stream_rejects_invalid_domain_and_seed(
    domain: object, seed: object
) -> None:
    with pytest.raises((TypeError, ValueError)):
        ShakeStream(domain=domain, seed=seed)  # type: ignore[arg-type]


def test_shake_stream_rejects_negative_read_count() -> None:
    stream = ShakeStream(domain=b"domain", seed=bytes(32))

    with pytest.raises(ValueError, match="nonnegative"):
        stream.read(-1)


@pytest.mark.parametrize("count", [True, 1.0, "1"])
def test_shake_stream_rejects_noninteger_read_count(count: object) -> None:
    stream = ShakeStream(domain=b"domain", seed=bytes(32))

    with pytest.raises(TypeError, match="integer"):
        stream.read(count)  # type: ignore[arg-type]


def test_randbelow_rejects_out_of_range_draws() -> None:
    stream = ShakeStream(domain=b"randbelow-3", seed=bytes(32))

    # The first stream bytes are 0x82, 0x1c, 0x3e.  For upper=129 the
    # rejection limit is 129, so 0x82 is discarded and 0x1c is accepted.
    assert stream.randbelow(129) == 28
    assert stream.read(1) == b"\x3e"


@pytest.mark.parametrize("upper", [0, -1])
def test_randbelow_rejects_nonpositive_upper_bound(upper: int) -> None:
    stream = ShakeStream(domain=b"domain", seed=bytes(32))

    with pytest.raises(ValueError, match="positive"):
        stream.randbelow(upper)


@pytest.mark.parametrize("upper", [True, 1.0, "1"])
def test_randbelow_rejects_noninteger_upper_bound(upper: object) -> None:
    stream = ShakeStream(domain=b"domain", seed=bytes(32))

    with pytest.raises(TypeError, match="integer"):
        stream.randbelow(upper)  # type: ignore[arg-type]


def test_streamed_matvec_matches_materialized_oracle(catalog: Catalog) -> None:
    instance = catalog.get("toy-uniform")
    rows = tuple(iter_rows(instance))
    secret = (1, 0, -1)
    oracle = tuple(
        sum(coefficient * value for coefficient, value in zip(row, secret))
        % instance.q
        for row in rows
    )

    assert matvec_mod(instance, secret) == oracle


def test_uniform_rows_are_stable_and_row_separated(catalog: Catalog) -> None:
    instance = catalog.get("toy-uniform")
    rows = tuple(iter_rows(instance))

    assert rows == _EXPECTED_ROWS["uniform"]
    assert tuple(iter_rows(instance)) == rows
    assert len(rows) == instance.m
    assert all(len(row) == instance.n for row in rows)
    assert all(0 <= value < instance.q for row in rows for value in row)
    assert len(set(rows)) > 1


@pytest.mark.parametrize("kind", tuple(_EXPECTED_ROWS))
def test_native_rows_match_python_and_reviewed_golden_rows(
    catalog: Catalog, matrix_ref_binary: Path, kind: str
) -> None:
    instance = _instance_for_kind(catalog, kind)
    native_rows = _native_rows(matrix_ref_binary, instance, start=0, stop=3)

    assert native_rows == materialize_row_block(instance, 0, 3)
    assert native_rows == _EXPECTED_ROWS[kind][:3]


@pytest.mark.parametrize("kind", tuple(_REJECTION_HEAVY_EXPECTED_ROWS))
def test_native_rejection_sampling_matches_reviewed_non_power_of_two_rows(
    catalog: Catalog, matrix_ref_binary: Path, kind: str
) -> None:
    instance = _rejection_heavy_instance(catalog, kind)
    native_rows = _native_rows(matrix_ref_binary, instance, start=0, stop=4)
    sampling_upper = (
        instance.q if kind == "uniform" else len(instance.matrix.alphabet)
    )

    assert sampling_upper == 129
    assert native_rows == materialize_rows(instance)
    assert native_rows == _REJECTION_HEAVY_EXPECTED_ROWS[kind]


@pytest.mark.parametrize("case", tuple(_UINT32_MAX_EXPECTED_ROWS))
def test_native_uint32_max_and_saturated_sparse_rows_match_python(
    catalog: Catalog, matrix_ref_binary: Path, case: str
) -> None:
    instance = _uint32_boundary_instance(catalog, case)
    native_rows = _native_rows(matrix_ref_binary, instance, start=0, stop=3)

    assert instance.q == 2**32 - 1
    assert native_rows == materialize_row_block(instance, 0, 3)
    assert native_rows == _UINT32_MAX_EXPECTED_ROWS[case]
    if case == "saturated_sparse":
        assert instance.matrix.row_weight == instance.n
        assert all(all(value != 0 for value in row) for row in native_rows)


def test_native_multi_row_range_matches_nonzero_python_slice(
    catalog: Catalog, matrix_ref_binary: Path
) -> None:
    instance = catalog.get("toy-uniform")

    assert _native_rows(matrix_ref_binary, instance, start=1, stop=4) == (
        _EXPECTED_ROWS["uniform"][1:4]
    )


@pytest.mark.parametrize("kind", tuple(_EXPECTED_ROWS))
def test_native_argv_contains_only_public_matrix_parameters(
    catalog: Catalog, matrix_ref_binary: Path, kind: str
) -> None:
    instance = _instance_for_kind(catalog, kind)
    arguments = _native_argv(matrix_ref_binary, instance, start=0, stop=3)
    flags = arguments[1::2]
    expected_flags = {
        "--seed",
        "--domain",
        "--instance-id",
        "--n",
        "--q",
        "--kind",
        "--start",
        "--stop",
    }
    if kind in {"small_alphabet", "sparse_small_alphabet"}:
        expected_flags.add("--alphabet")
    if kind in {"sparse_uniform", "sparse_small_alphabet"}:
        expected_flags.add("--row-weight")

    assert len(flags) == len(set(flags))
    assert set(flags) == expected_flags
    assert not any(
        forbidden in argument.lower()
        for forbidden in ("secret", "error", "residual")
        for argument in arguments
    )


def test_native_cli_rejects_malformed_invocation_without_stdout(
    matrix_ref_binary: Path,
) -> None:
    completed = subprocess.run(
        [str(matrix_ref_binary), "--seed", "not-a-seed"],
        check=False,
        capture_output=True,
        text=True,
        timeout=_NATIVE_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr.startswith("error:")


def test_native_subprocess_calls_always_have_finite_timeouts() -> None:
    syntax_tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    subprocess_calls = [
        node
        for node in ast.walk(syntax_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
    ]

    assert subprocess_calls
    assert all(
        any(keyword.arg == "timeout" for keyword in call.keywords)
        for call in subprocess_calls
    )


def test_small_alphabet_rows_are_stable_and_row_separated(catalog: Catalog) -> None:
    instance = _small_alphabet_instance(catalog)
    rows = tuple(iter_rows(instance))

    assert rows == _EXPECTED_ROWS["small_alphabet"]
    assert tuple(iter_rows(instance)) == rows
    assert len(rows) == instance.m
    assert all(len(row) == instance.n for row in rows)
    assert all(value in instance.matrix.alphabet for row in rows for value in row)
    assert len(set(rows)) > 1


def test_sparse_uniform_rows_are_stable_and_exact_weight(catalog: Catalog) -> None:
    instance = _sparse_uniform_instance(catalog)
    rows = tuple(iter_rows(instance))

    assert rows == _EXPECTED_ROWS["sparse_uniform"]
    assert tuple(iter_rows(instance)) == rows
    assert len(rows) == instance.m
    assert all(len(row) == instance.n for row in rows)
    assert all(sum(value != 0 for value in row) == 2 for row in rows)
    assert all(0 <= value < instance.q for row in rows for value in row)
    assert len(set(rows)) > 1


def test_sparse_small_alphabet_rows_are_stable_and_exact_weight(
    catalog: Catalog,
) -> None:
    instance = catalog.get("toy-sparse")
    rows = tuple(iter_rows(instance))

    assert rows == _EXPECTED_ROWS["sparse_small_alphabet"]
    assert tuple(iter_rows(instance)) == rows
    assert len(rows) == instance.m
    assert all(len(row) == instance.n for row in rows)
    assert all(sum(value != 0 for value in row) == 2 for row in rows)
    assert all(
        value == 0 or value in instance.matrix.alphabet
        for row in rows
        for value in row
    )
    assert len(set(rows)) > 1


def test_materialize_row_block_matches_requested_slice(catalog: Catalog) -> None:
    instance = catalog.get("toy-uniform")
    rows = materialize_rows(instance)

    assert rows == _EXPECTED_ROWS["uniform"]
    assert materialize_row_block(instance, 1, 3) == rows[1:3]
    assert materialize_row_block(instance, 2, 2) == ()


@pytest.mark.parametrize(
    ("start", "stop", "error"),
    [
        (True, 1, TypeError),
        (0, False, TypeError),
        (0.0, 1, TypeError),
        (0, 1.0, TypeError),
        (-1, 1, ValueError),
        (2, 1, ValueError),
        (0, 5, ValueError),
    ],
)
def test_materialize_row_block_rejects_invalid_bounds(
    catalog: Catalog, start: object, stop: object, error: type[Exception]
) -> None:
    instance = catalog.get("toy-uniform")

    with pytest.raises(error):
        materialize_row_block(
            instance,
            start,  # type: ignore[arg-type]
            stop,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("secret", "error"),
    [
        ((1, 2), ValueError),
        ((1, 2, 3, 4), ValueError),
        ((1, True, 3), TypeError),
        ((1, 2.0, 3), TypeError),
    ],
)
def test_matvec_rejects_invalid_secret(
    catalog: Catalog, secret: object, error: type[Exception]
) -> None:
    instance = catalog.get("toy-uniform")

    with pytest.raises(error):
        matvec_mod(instance, secret)  # type: ignore[arg-type]
