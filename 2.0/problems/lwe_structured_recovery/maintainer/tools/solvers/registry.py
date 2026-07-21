"""Small, lazy registry for the public reference-recovery solvers."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


FAMILIES = frozenset(
    {
        "DS_BIN",
        "DS_TER",
        "DS_SMALL",
        "SA_Q",
        "SA_SMALL",
        "DA_BIN",
        "DA_TER",
        "MIX_Q_SPARSE",
        "MIX_SMALL_SPARSE",
        "MIX_DENSE_SMALL",
    }
)
ORIGINS = frozenset(
    {"paper_method", "original_clean_room", "folklore_adaptation"}
)
_SOLVER_KEYS = frozenset(
    {
        "id",
        "entrypoint",
        "applicability",
        "task",
        "randomized",
        "families",
        "origin",
        "method_sources",
        "context_sources",
        "paper_case_eligible",
    }
)
_SOURCE_KEYS = frozenset(
    {
        "id",
        "title",
        "authors",
        "publication_version",
        "revision_date",
        "versioned_url",
        "pdf_sha256",
        "retrieved_at",
        "locator",
        "source_role",
        "hypotheses",
        "implementation_mapping",
        "paper_license",
        "software",
        "copied_or_modified_files",
        "clean_room_attestation",
        "notice_obligations",
    }
)
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z", re.ASCII)
_ENTRYPOINT = re.compile(
    r"[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PACKAGE_DIR = Path(__file__).resolve().parent
_APP_DIR = _PACKAGE_DIR.parents[1]
_LOCAL_SOLVER_DEPENDENCIES: Mapping[str, tuple[str, ...]] = {
    "tools.solvers.__init__": (),
    "tools.solvers.api": (),
    "tools.solvers.bounded_error": ("tools.solvers.api",),
    "tools.solvers.mixed_recovery": (
        "tools.solvers.api",
        "tools.solvers.sparse_matrix",
    ),
    "tools.solvers.primal_bdd": (
        "tools.solvers.api",
        "tools.solvers.bounded_error",
    ),
    # The hybrid imports PrimalBDD inside its validated body for nested recovery.
    "tools.solvers.small_secret_hybrid": (
        "tools.solvers.api",
        "tools.solvers.bounded_error",
        "tools.solvers.primal_bdd",
    ),
    "tools.solvers.support_incidence": ("tools.solvers.api",),
    "tools.solvers.sparse_matrix": ("tools.solvers.api",),
    "tools.solvers.sparse_secret": ("tools.solvers.api",),
}


class RegistryError(ValueError):
    """A checked-in registry resource is malformed or inconsistent."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SolverRecord:
    solver_id: str
    entrypoint: str
    applicability: str
    task: str
    randomized: bool
    families: tuple[str, ...]
    origin: str
    method_sources: tuple[str, ...]
    context_sources: tuple[str, ...]
    paper_case_eligible: bool


@dataclass(frozen=True, slots=True)
class SolverImplementationReceipt:
    solver_id: str
    entrypoint: str
    implementation_digest: str
    source_files: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceRecord:
    source_id: str
    title: str
    authors: tuple[str, ...]
    publication_version: str
    revision_date: str
    versioned_url: str
    pdf_sha256: str
    retrieved_at: str
    locator: str
    source_role: str
    hypotheses: tuple[str, ...]
    implementation_mapping: str
    paper_license: str
    notice_obligations: tuple[str, ...]


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot read registry resource: {path.name}") from exc
    if type(value) is not dict:
        raise RegistryError(f"{path.name} root must be an object")
    return value


def _strings(value: object, where: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise RegistryError(f"{where} must be an array of strings")
    return tuple(value)


def _text(value: object, where: str) -> str:
    if type(value) is not str or not value.strip():
        raise RegistryError(f"{where} must be nonempty text")
    return value


def load_sources(path: Path | None = None) -> Mapping[str, SourceRecord]:
    document = _load(_PACKAGE_DIR / "sources.json" if path is None else path)
    if set(document) != {"schema_version", "sources"} or document.get(
        "schema_version"
    ) != 1:
        raise RegistryError("source registry header is invalid")
    raw_sources = document.get("sources")
    if type(raw_sources) is not list:
        raise RegistryError("sources must be an array")
    result: dict[str, SourceRecord] = {}
    for index, raw in enumerate(raw_sources):
        if type(raw) is not dict or set(raw) != _SOURCE_KEYS:
            raise RegistryError(f"sources[{index}] has invalid fields")
        source_id = _text(raw["id"], f"sources[{index}].id")
        if not _IDENTIFIER.fullmatch(source_id) or source_id in result:
            raise RegistryError(f"sources[{index}].id is invalid or duplicated")
        digest = _text(raw["pdf_sha256"], f"sources[{index}].pdf_sha256")
        if not _SHA256.fullmatch(digest):
            raise RegistryError(f"sources[{index}].pdf_sha256 is invalid")
        url = _text(raw["versioned_url"], f"sources[{index}].versioned_url")
        if not url.startswith("https://"):
            raise RegistryError(f"sources[{index}].versioned_url must use HTTPS")
        result[source_id] = SourceRecord(
            source_id=source_id,
            title=_text(raw["title"], "source title"),
            authors=_strings(raw["authors"], "source authors"),
            publication_version=_text(raw["publication_version"], "publication"),
            revision_date=_text(raw["revision_date"], "revision date"),
            versioned_url=url,
            pdf_sha256=digest,
            retrieved_at=_text(raw["retrieved_at"], "retrieval date"),
            locator=_text(raw["locator"], "source locator"),
            source_role=_text(raw["source_role"], "source role"),
            hypotheses=_strings(raw["hypotheses"], "source hypotheses"),
            implementation_mapping=_text(
                raw["implementation_mapping"], "implementation mapping"
            ),
            paper_license=_text(raw["paper_license"], "paper license"),
            notice_obligations=_strings(
                raw["notice_obligations"], "notice obligations"
            ),
        )
    return result


def load_registry(path: Path | None = None) -> tuple[SolverRecord, ...]:
    document = _load(_PACKAGE_DIR / "registry.json" if path is None else path)
    if set(document) != {"schema_version", "solvers"} or document.get(
        "schema_version"
    ) != 1:
        raise RegistryError("solver registry header is invalid")
    raw_solvers = document.get("solvers")
    if type(raw_solvers) is not list:
        raise RegistryError("solvers must be an array")
    known_sources = load_sources()
    records: list[SolverRecord] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_solvers):
        if type(raw) is not dict or set(raw) != _SOLVER_KEYS:
            raise RegistryError(f"solvers[{index}] has invalid fields")
        solver_id = _text(raw["id"], f"solvers[{index}].id")
        entrypoint = _text(raw["entrypoint"], "solver entrypoint")
        applicability = _text(raw["applicability"], "applicability entrypoint")
        if (
            not _IDENTIFIER.fullmatch(solver_id)
            or solver_id in seen
            or not _ENTRYPOINT.fullmatch(entrypoint)
            or not _ENTRYPOINT.fullmatch(applicability)
        ):
            raise RegistryError(f"solvers[{index}] identity is invalid")
        families = _strings(raw["families"], "solver families")
        method_sources = _strings(raw["method_sources"], "method sources")
        context_sources = _strings(raw["context_sources"], "context sources")
        if not families or not set(families) <= FAMILIES:
            raise RegistryError(f"solvers[{index}] families are invalid")
        if not set(method_sources + context_sources) <= set(known_sources):
            raise RegistryError(f"solvers[{index}] cites an unknown source")
        if type(raw["randomized"]) is not bool or type(
            raw["paper_case_eligible"]
        ) is not bool:
            raise RegistryError(f"solvers[{index}] boolean field is invalid")
        origin = _text(raw["origin"], "solver origin")
        if origin not in ORIGINS or raw["task"] != "exact_search":
            raise RegistryError(f"solvers[{index}] classification is invalid")
        seen.add(solver_id)
        records.append(
            SolverRecord(
                solver_id=solver_id,
                entrypoint=entrypoint,
                applicability=applicability,
                task="exact_search",
                randomized=raw["randomized"],
                families=families,
                origin=origin,
                method_sources=method_sources,
                context_sources=context_sources,
                paper_case_eligible=raw["paper_case_eligible"],
            )
        )
    if not records:
        raise RegistryError("solver registry is empty")
    return tuple(records)


def _resolve(reference: str) -> object:
    module_name, symbol = reference.split(":", 1)
    try:
        return getattr(importlib.import_module(module_name), symbol)
    except (AttributeError, ImportError) as exc:
        raise RegistryError(f"cannot resolve {reference}") from exc


def _canonical_record(record: SolverRecord) -> SolverRecord:
    matches = tuple(item for item in load_registry() if item.solver_id == record.solver_id)
    if len(matches) != 1 or matches[0] != record:
        raise RegistryError("solver record is not canonical")
    return matches[0]


def _implementation_modules(record: SolverRecord) -> tuple[str, ...]:
    pending = [
        "tools.solvers.__init__",
        record.entrypoint.split(":", 1)[0],
        record.applicability.split(":", 1)[0],
    ]
    modules: set[str] = set()
    while pending:
        module_name = pending.pop()
        if module_name in modules:
            continue
        dependencies = _LOCAL_SOLVER_DEPENDENCIES.get(module_name)
        if dependencies is None:
            raise RegistryError("solver module is absent from the dependency roster")
        modules.add(module_name)
        pending.extend(dependencies)
    return tuple(sorted(modules))


def _canonical_record_payload(record: SolverRecord) -> dict[str, object]:
    return {
        "id": record.solver_id,
        "entrypoint": record.entrypoint,
        "applicability": record.applicability,
        "task": record.task,
        "randomized": record.randomized,
        "families": record.families,
        "origin": record.origin,
        "method_sources": record.method_sources,
        "context_sources": record.context_sources,
        "paper_case_eligible": record.paper_case_eligible,
    }


def canonical_solver_implementation_receipt(
    record: SolverRecord,
) -> SolverImplementationReceipt:
    canonical = _canonical_record(record)
    source_files: list[tuple[str, str]] = []
    for module_name in _implementation_modules(canonical):
        relative = module_name.replace(".", "/") + ".py"
        source_path = (_APP_DIR / relative).resolve()
        try:
            if source_path.relative_to(_PACKAGE_DIR).parent != Path("."):
                raise ValueError
            source_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        except (OSError, ValueError) as exc:
            raise RegistryError("solver dependency is outside the packaged app") from exc
        source_files.append((relative, source_digest))
    descriptor = json.dumps(
        {
            "format": "solver-implementation-v2",
            "record": _canonical_record_payload(canonical),
            "source_files": source_files,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return SolverImplementationReceipt(
        solver_id=canonical.solver_id,
        entrypoint=canonical.entrypoint,
        implementation_digest=hashlib.sha256(descriptor).hexdigest(),
        source_files=tuple(source_files),
    )


def instantiate_solver(record: SolverRecord):
    from .api import ValidatedExactSolver

    canonical = _canonical_record(record)
    solver_type = _resolve(canonical.entrypoint)
    if not isinstance(solver_type, type) or not issubclass(solver_type, ValidatedExactSolver):
        raise RegistryError(f"{canonical.entrypoint} is not a solver class")
    solver = solver_type()
    if type(solver).solve is not ValidatedExactSolver.solve:
        raise RegistryError("solver overrides the common validation wrapper")
    if solver.solver_id != canonical.solver_id:
        raise RegistryError("solver_id differs from the registry")
    return solver


def require_registry_instance(solver: object) -> SolverImplementationReceipt:
    matches: list[SolverRecord] = []
    for record in load_registry():
        candidate = _resolve(record.entrypoint)
        if type(solver) is candidate:
            matches.append(record)
    if len(matches) != 1 or getattr(solver, "solver_id", None) != matches[0].solver_id:
        raise RegistryError("solver concrete type is not registered")
    return canonical_solver_implementation_receipt(matches[0])


def resolve_applicability(record: SolverRecord):
    canonical = _canonical_record(record)
    value = _resolve(canonical.applicability)
    if not callable(value):
        raise RegistryError("applicability entrypoint is not callable")
    return value


def render_third_party_notices(sources: Mapping[str, SourceRecord]) -> str:
    lines = ["# Third-party notices", ""]
    for source_id in sorted(sources):
        source = sources[source_id]
        lines.extend(
            [
                f"## {source.title}",
                "",
                f"Authors: {', '.join(source.authors)}",
                f"Source: {source.versioned_url}",
                f"License: {source.paper_license}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "RegistryError",
    "SolverImplementationReceipt",
    "SolverRecord",
    "SourceRecord",
    "canonical_solver_implementation_receipt",
    "instantiate_solver",
    "load_registry",
    "load_sources",
    "render_third_party_notices",
    "require_registry_instance",
    "resolve_applicability",
]
