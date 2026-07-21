"""Validated exact-recovery solver interfaces."""

from .api import (
    CheckpointStore,
    ExactProblem,
    ExactSolver,
    ValidatedExactSolver,
    ProgressEvent,
    SolveRequest,
    SolveResult,
    SolveStatus,
    SolverContractError,
    append_progress,
    scrub_result,
    validate_solve_result,
)

__all__ = (
    "CheckpointStore",
    "ExactProblem",
    "ExactSolver",
    "ValidatedExactSolver",
    "ProgressEvent",
    "SolveRequest",
    "SolveResult",
    "SolveStatus",
    "SolverContractError",
    "append_progress",
    "scrub_result",
    "validate_solve_result",
)
