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
