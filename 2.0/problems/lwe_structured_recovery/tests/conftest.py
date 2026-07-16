from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from lwe_challenge.schema import Catalog


SOLVER_FIXTURE_IDS = (
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


TASK_DIR = Path(__file__).resolve().parents[1]
APP_DIR = TASK_DIR / "harbor" / "app"
PUBLIC_DIR = APP_DIR / "public"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

sys.path[:0] = [str(TASK_DIR), str(APP_DIR), str(PUBLIC_DIR)]


def load_task_module(path: Path, module_name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load task module: {module_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


@pytest.fixture
def task_dir() -> Path:
    return TASK_DIR


@pytest.fixture
def catalog_path() -> Path:
    return FIXTURES_DIR / "catalog_two_instances.json"


@pytest.fixture
def catalog(catalog_path: Path) -> Catalog:
    from lwe_challenge.schema import Catalog

    return Catalog.load(catalog_path)


@pytest.fixture
def valid_submission_bytes() -> bytes:
    return (FIXTURES_DIR / "submission_one_valid.json").read_bytes()


@pytest.fixture
def task_module_loader() -> Callable[[Path, str], ModuleType]:
    return load_task_module


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "recovery: executes an exact secret-recovery fixture",
    )
    config.addinivalue_line(
        "markers",
        "post_recovery: audits recovery outputs without executing solvers",
    )


@pytest.fixture
def solver_catalog_path() -> Path:
    return FIXTURES_DIR / "solver_catalog.json"


@pytest.fixture
def solver_catalog(solver_catalog_path: Path):
    import lwe_instance

    return lwe_instance.Catalog.load(solver_catalog_path)


def _solver_instance_fixture(instance_id: str):
    @pytest.fixture(name=instance_id)
    def fixture(solver_catalog):
        return solver_catalog.get(instance_id)

    return fixture


for _fixture_id in SOLVER_FIXTURE_IDS:
    globals()[_fixture_id] = _solver_instance_fixture(_fixture_id)
