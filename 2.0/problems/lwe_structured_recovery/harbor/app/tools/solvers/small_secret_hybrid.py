"""Small-secret hybrid: declared coordinate guesses plus registered PrimalBDD."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .api import (
    ExactProblem,
    ValidatedExactSolver,
    SolveRequest,
    SolveResult,
    SolveStatus,
    SolverContractError,
)
from .bounded_error import (
    MemoryLimitExceeded,
    SolverRunControl,
    TimeLimitExceeded,
    is_prime,
    memory_cap_bytes,
)


@dataclass(frozen=True, slots=True)
class HybridPartition:
    remaining: tuple[int, ...]
    guessed: tuple[int, ...]


class NestedDispatchError(RuntimeError):
    """The reviewed nested solver could not be resolved from the registry."""


def hybrid_partition(*, n: int, guessed_count: int) -> HybridPartition:
    if type(n) is not int or n <= 1:
        raise ValueError("n must exceed one")
    if type(guessed_count) is not int or not 0 < guessed_count < n:
        raise ValueError("guessed_count must be between one and n-1")
    split = n - guessed_count
    return HybridPartition(tuple(range(split)), tuple(range(split, n)))


def merge_secret(
    partition: HybridPartition,
    *,
    remaining_values: Sequence[int],
    guessed_values: Sequence[int],
) -> tuple[int, ...]:
    remaining = tuple(remaining_values)
    guessed = tuple(guessed_values)
    if len(remaining) != len(partition.remaining) or len(guessed) != len(partition.guessed):
        raise ValueError("hybrid values do not match the partition")
    n = len(partition.remaining) + len(partition.guessed)
    merged: list[int | None] = [None] * n
    for index, value in zip(partition.remaining, remaining, strict=True):
        merged[index] = value
    for index, value in zip(partition.guessed, guessed, strict=True):
        merged[index] = value
    if any(value is None for value in merged):
        raise ValueError("hybrid partition does not cover every coordinate")
    return tuple(value for value in merged if value is not None)


def build_nested_request(
    outer: SolveRequest,
    *,
    seed: int,
    remaining_seconds: float,
    parameters: Mapping[str, object],
    exclude_secret: tuple[int, ...] | None = None,
    work_dir: Path | None = None,
    resume_checkpoint: Path | None = None,
) -> SolveRequest:
    if remaining_seconds <= 0:
        raise ValueError("remaining_seconds must be positive")
    return SolveRequest(
        seed=seed,
        max_seconds=remaining_seconds,
        work_dir=Path(outer.work_dir) if work_dir is None else work_dir,
        single_worker=True,
        exclude_secret=exclude_secret,
        parameters=parameters,
        resume_checkpoint=resume_checkpoint,
        checkpoint_every_work_units=outer.checkpoint_every_work_units,
    )


def nested_exclusion_for_guess(
    partition: HybridPartition,
    *,
    guessed_values: Sequence[int],
    outer_exclude_secret: tuple[int, ...] | None,
) -> tuple[int, ...] | None:
    """Translate a full excluded witness only for its matching outer guess."""

    if outer_exclude_secret is None:
        return None
    n = len(partition.remaining) + len(partition.guessed)
    guessed = tuple(guessed_values)
    if len(outer_exclude_secret) != n or len(guessed) != len(partition.guessed):
        return None
    if tuple(outer_exclude_secret[index] for index in partition.guessed) != guessed:
        return None
    return tuple(outer_exclude_secret[index] for index in partition.remaining)


def propagate_nested_result(
    result: SolveResult,
    *,
    elapsed_seconds: float,
    outer_work_units: int,
) -> SolveResult:
    if result.status is SolveStatus.SUCCESS:
        raise ValueError("successful nested result must be merged and validated")
    work_units = outer_work_units + result.work_units
    if result.status is SolveStatus.ERROR:
        return SolveResult.error(
            elapsed_seconds=elapsed_seconds,
            work_units=work_units,
            peak_rss_bytes=result.peak_rss_bytes,
            checkpoint_count=result.checkpoint_count,
            detail={"code": "nested_primal_error"},
        )
    if result.status is SolveStatus.CENSORED:
        return SolveResult.censored(
            elapsed_seconds=elapsed_seconds,
            work_units=work_units,
            peak_rss_bytes=result.peak_rss_bytes,
            checkpoint_count=result.checkpoint_count,
            detail={"code": "nested_primal_censored"},
        )
    # Nested exhaustion is not, by itself, a certificate for the complete
    # outer guess domain.  Keep the outer result censored until such a
    # certificate is assembled and verified (this implementation never does).
    return SolveResult.censored(
        elapsed_seconds=elapsed_seconds,
        work_units=work_units,
        peak_rss_bytes=result.peak_rss_bytes,
        checkpoint_count=result.checkpoint_count,
        detail={"code": "nested_primal_exhausted_without_outer_certificate"},
    )


def _guessed_count(instance: ExactProblem, request: SolveRequest | None) -> int:
    default = min(2, instance.n - 1)
    value = default if request is None else request.parameters.get("hybrid_guess_count", default)
    if type(value) is not int or not 0 < value < instance.n:
        raise ValueError("hybrid_guess_count must be between one and n-1")
    return value


def applicability(instance: ExactProblem, request: SolveRequest | None = None) -> bool:
    if (
        instance.family not in {"DS_SMALL", "MIX_DENSE_SMALL"}
        or instance.secret_predicate_kind != "alphabet"
        or type(instance.n) is not int
        or instance.n <= 1
        or not is_prime(getattr(instance, "q", 0))
    ):
        return False
    alphabet = tuple(instance.secret_alphabet)
    if not alphabet or len(alphabet) != len(set(alphabet)) or len(alphabet) > 9:
        return False
    try:
        _guessed_count(instance, request)
    except ValueError:
        return False
    return True


def _centered(value: int, q: int) -> int:
    residue = value % q
    return residue - q if residue >= (q + 1) // 2 else residue


class _ReducedProblem:
    """Array-backed public problem assembled only from public rows and a guess."""

    def __init__(
        self,
        *,
        parent: ExactProblem,
        rows: tuple[tuple[int, ...], ...],
        rhs: tuple[int, ...],
        min_nonzero: int,
        max_nonzero: int,
        guess_index: int,
    ) -> None:
        self.instance_id = f"{parent.instance_id}.hybrid-{guess_index}"
        self.instance_digest = hashlib.sha256(
            (
                "hybrid-public-reduction-v1:"
                f"{parent.instance_digest}:{guess_index}"
            ).encode("ascii")
        ).hexdigest()
        self.n = len(rows[0])
        self.m = len(rows)
        self.q = parent.q
        self.b = rhs
        self.family = parent.family
        self.secret_predicate_kind = parent.secret_predicate_kind
        self.secret_alphabet = parent.secret_alphabet
        self.secret_min_nonzero = min_nonzero
        self.secret_max_nonzero = max_nonzero
        self.error_max_abs = parent.error_max_abs
        self.error_max_l1 = parent.error_max_l1
        self.error_max_l2_squared = parent.error_max_l2_squared
        self.error_max_nonzero = parent.error_max_nonzero
        self._rows = rows

    def materialize_rows(self) -> tuple[tuple[int, ...], ...]:
        return self._rows

    def materialize_row_block(
        self,
        start: int,
        stop: int,
    ) -> tuple[tuple[int, ...], ...]:
        if (
            type(start) is not int
            or type(stop) is not int
            or not 0 <= start <= stop <= self.m
        ):
            raise ValueError("row block bounds are invalid")
        return self._rows[start:stop]

    def validate_secret(self, secret: Sequence[int]):
        values = tuple(secret)
        if (
            len(values) != self.n
            or any(type(value) is not int or value not in self.secret_alphabet for value in values)
            or not self.secret_min_nonzero <= sum(value != 0 for value in values) <= self.secret_max_nonzero
        ):
            return _Verdict(False)
        residuals = tuple(
            _centered(
                target - sum(coefficient * value for coefficient, value in zip(row, values, strict=True)),
                self.q,
            )
            for row, target in zip(self._rows, self.b, strict=True)
        )
        absolute = tuple(abs(value) for value in residuals)
        ok = (
            all(value <= self.error_max_abs for value in absolute)
            and (self.error_max_l1 is None or sum(absolute) <= self.error_max_l1)
            and (
                self.error_max_l2_squared is None
                or sum(value * value for value in residuals) <= self.error_max_l2_squared
            )
            and (
                self.error_max_nonzero is None
                or sum(value != 0 for value in residuals) <= self.error_max_nonzero
            )
        )
        return _Verdict(ok)


@dataclass(frozen=True, slots=True)
class _Verdict:
    ok: bool


def _reduced_problem(
    instance: ExactProblem,
    partition: HybridPartition,
    guessed_values: tuple[int, ...],
    *,
    guess_index: int,
    control: SolverRunControl,
) -> _ReducedProblem:
    if len(instance.b) != instance.m:
        raise ValueError("public instance dimensions disagree")
    estimate = (
        16_384
        + instance.m * len(partition.remaining) * 128
        + instance.m * 192
        + instance.n * 256
    )
    control.preflight(estimate)
    reduced_rows: list[tuple[int, ...]] = []
    rhs: list[int] = []
    for row_index in range(instance.m):
        reason = control.stop_reason()
        if reason == "memory_cap":
            raise MemoryLimitExceeded
        if reason == "time_cap":
            raise TimeLimitExceeded
        block = instance.materialize_row_block(row_index, row_index + 1)
        if len(block) != 1 or len(block[0]) != instance.n:
            raise ValueError("public instance dimensions disagree")
        row = block[0]
        reduced_rows.append(tuple(row[index] for index in partition.remaining))
        guessed_contribution = 0
        for index, value in zip(
            partition.guessed,
            guessed_values,
            strict=True,
        ):
            reason = control.stop_reason()
            if reason == "memory_cap":
                raise MemoryLimitExceeded
            if reason == "time_cap":
                raise TimeLimitExceeded
            guessed_contribution += row[index] * value
        rhs.append(
            (
                instance.b[row_index]
                - guessed_contribution
            )
            % instance.q
        )
        control.preflight(0)
    guessed_nonzero = sum(value != 0 for value in guessed_values)
    remaining_count = len(partition.remaining)
    minimum = max(0, instance.secret_min_nonzero - guessed_nonzero)
    maximum = min(remaining_count, instance.secret_max_nonzero - guessed_nonzero)
    if maximum < minimum:
        raise ValueError("guess violates the public nonzero predicate")
    return _ReducedProblem(
        parent=instance,
        rows=tuple(reduced_rows),
        rhs=tuple(rhs),
        min_nonzero=minimum,
        max_nonzero=maximum,
        guess_index=guess_index,
    )


def dispatch_registered_primal(instance: ExactProblem, request: SolveRequest) -> SolveResult:
    """Invoke the bundled primal fallback without per-guess registry auditing."""

    try:
        from .primal_bdd import PrimalBDD
    except ImportError as exc:
        raise NestedDispatchError("primal_bdd solver cannot be imported") from exc
    return PrimalBDD().solve(instance, request)


def _primal_parameters(
    request: SolveRequest,
    *,
    remaining_work_units: int | None = None,
) -> dict[str, object]:
    allowed = {
        "primal_bkz_block_size",
        "primal_cvp_mode",
        "primal_exact_verification_cap",
        "memory_cap_bytes",
        "work_unit_cap",
    }
    selected = {
        key: request.parameters[key]
        for key in allowed
        if key in request.parameters
    }
    if remaining_work_units is not None:
        selected["work_unit_cap"] = remaining_work_units
    return selected


def _positive_cap(request: SolveRequest, domain_size: int) -> int:
    value = request.parameters.get("hybrid_work_unit_cap", domain_size)
    if type(value) is not int or value <= 0:
        raise ValueError("hybrid_work_unit_cap must be positive")
    return value


def _global_work_cap(request: SolveRequest) -> int:
    value = request.parameters.get("work_unit_cap", 2_000_000)
    if type(value) is not int or value <= 0:
        raise ValueError("work_unit_cap must be positive")
    return value


def _guess_at_ordinal(
    alphabet: tuple[int, ...],
    width: int,
    ordinal: int,
) -> tuple[int, ...]:
    if not 0 <= ordinal < len(alphabet) ** width:
        raise ValueError("hybrid guess ordinal is out of range")
    values = [alphabet[0]] * width
    remaining = ordinal
    for index in range(width - 1, -1, -1):
        remaining, digit = divmod(remaining, len(alphabet))
        values[index] = alphabet[digit]
    return tuple(values)


class SmallSecretHybrid(ValidatedExactSolver):
    solver_id = "small_secret_hybrid"
    solver_revision = "small-secret-hybrid-v2"

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        if not applicability(instance, request):
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "inapplicable_small_secret_hybrid"},
            )
        try:
            partition = hybrid_partition(n=instance.n, guessed_count=_guessed_count(instance, request))
            alphabet = tuple(instance.secret_alphabet)
            domain_size = len(alphabet) ** len(partition.guessed)
            cap = _positive_cap(request, domain_size)
            global_work_cap = _global_work_cap(request)
            memory_cap = memory_cap_bytes(request)
            control = SolverRunControl.create(
                instance=instance,
                request=request,
                solver_id=self.solver_id,
                solver_revision=self.solver_revision,
                search_descriptor={
                    "algorithm": "small_secret_hybrid_v2",
                    "partition_remaining": partition.remaining,
                    "partition_guessed": partition.guessed,
                    "alphabet": alphabet,
                    "domain_size": domain_size,
                    "outer_cap": cap,
                    "global_work_unit_cap": global_work_cap,
                },
                memory_cap_bytes=memory_cap,
            )
            state = control.solver_state
            base_state_keys = frozenset(
                {"nested_checkpoint_count", "nested_peak_rss_bytes"}
            )
            active_state_keys = base_state_keys | frozenset(
                {
                    "active_guess_index",
                    "active_nested_max_seconds",
                    "active_nested_run_id",
                    "pending_candidate",
                }
            )
            state_keys = frozenset(state)
            if state_keys not in (
                frozenset(),
                base_state_keys,
                active_state_keys,
            ):
                raise SolverContractError("checkpoint run state is malformed")
            nested_checkpoint_count = state.get("nested_checkpoint_count", 0)
            nested_peak_rss = state.get("nested_peak_rss_bytes", 0)
            active_guess_index = state.get("active_guess_index")
            active_nested_max_seconds = state.get("active_nested_max_seconds")
            active_nested_run_id = state.get("active_nested_run_id")
            raw_pending_candidate = state.get("pending_candidate")
            if raw_pending_candidate is None:
                pending_candidate: tuple[int, ...] | None = None
            elif type(raw_pending_candidate) in (list, tuple):
                pending_candidate = tuple(raw_pending_candidate)
            else:
                raise SolverContractError("checkpoint run state is malformed")
            reuse_nested_checkpoint = state_keys == active_state_keys
            if (
                type(nested_checkpoint_count) is not int
                or nested_checkpoint_count < 0
                or type(nested_peak_rss) is not int
                or nested_peak_rss < 0
                or not 0 <= control.cursor <= min(cap, domain_size)
                or control.work_units < control.cursor
                or control.work_units > global_work_cap
                or (
                    state_keys == active_state_keys
                    and (
                        type(active_guess_index) is not int
                        or active_guess_index != control.cursor
                        or not 0 <= active_guess_index < domain_size
                        or type(active_nested_max_seconds) not in (int, float)
                        or isinstance(active_nested_max_seconds, bool)
                        or not 0.0 < float(active_nested_max_seconds)
                        < float("inf")
                        or type(active_nested_run_id) is not str
                        or len(active_nested_run_id) != 32
                        or any(
                            character not in "0123456789abcdef"
                            for character in active_nested_run_id
                        )
                        or (
                            pending_candidate is not None
                            and (
                                len(pending_candidate) != instance.n
                                or any(
                                    type(value) is not int
                                    for value in pending_candidate
                                )
                            )
                        )
                    )
                )
            ):
                raise SolverContractError("checkpoint run state is malformed")
        except SolverContractError:
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "checkpoint_invalid"},
            )
        except (AttributeError, TypeError, ValueError):
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "invalid_public_parameters"},
            )

        def state_payload() -> dict[str, object]:
            payload: dict[str, object] = {
                "nested_checkpoint_count": nested_checkpoint_count,
                "nested_peak_rss_bytes": nested_peak_rss,
            }
            if active_guess_index is not None:
                assert active_nested_max_seconds is not None
                assert active_nested_run_id is not None
                payload.update(
                    {
                        "active_guess_index": active_guess_index,
                        "active_nested_max_seconds": active_nested_max_seconds,
                        "active_nested_run_id": active_nested_run_id,
                        "pending_candidate": pending_candidate,
                    }
                )
            return payload

        def censored(reason: str, *, phase: str, outer_cap: bool = False) -> SolveResult:
            control.advance(
                cursor=control.cursor,
                work_units=control.work_units,
                solver_state=state_payload(),
            )
            try:
                control.checkpoint(force=True, phase=phase)
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                    checkpoint_count=control.checkpoint_count
                    + nested_checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )
            parameters: dict[str, object] = {
                "domain_size": domain_size,
                "tested_count": control.cursor
                + (1 if active_guess_index is not None else 0),
            }
            if reason == "memory_cap":
                parameters.update(
                    {
                        "cap": memory_cap,
                        "cap_unit": "bytes",
                        "memory_cap_bytes": memory_cap,
                    }
                )
            elif reason == "work_unit_cap":
                parameters.update(
                    {
                        "cap": cap if outer_cap else global_work_cap,
                        "cap_unit": "candidates" if outer_cap else "work_units",
                        "work_unit_cap": cap if outer_cap else global_work_cap,
                    }
                )
            return SolveResult.censored(
                elapsed_seconds=control.elapsed_seconds,
                work_units=control.work_units,
                peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                checkpoint_count=control.checkpoint_count
                + nested_checkpoint_count,
                detail={"reason": reason, "public_parameters": parameters},
            )

        while control.cursor < domain_size:
            if control.cursor >= cap:
                return censored(
                    "work_unit_cap",
                    phase="hybrid_outer_cap",
                    outer_cap=True,
                )
            reason = control.stop_reason()
            if reason is not None:
                return censored(reason, phase=f"hybrid_{reason}")
            guess_index = control.cursor
            if pending_candidate is not None:
                candidate = pending_candidate
                if candidate == request.exclude_secret:
                    active_guess_index = None
                    active_nested_max_seconds = None
                    active_nested_run_id = None
                    pending_candidate = None
                    reuse_nested_checkpoint = False
                    control.advance(
                        cursor=guess_index + 1,
                        work_units=control.work_units,
                        solver_state=state_payload(),
                    )
                    try:
                        control.checkpoint(phase="hybrid_guess_complete")
                    except SolverContractError:
                        return SolveResult.error(
                            elapsed_seconds=control.elapsed_seconds,
                            work_units=control.work_units,
                            peak_rss_bytes=max(
                                control.observe_peak(), nested_peak_rss
                            ),
                            checkpoint_count=control.checkpoint_count
                            + nested_checkpoint_count,
                            detail={"code": "checkpoint_failure"},
                        )
                    continue
                verdict = instance.validate_secret(candidate)
                reason = control.stop_reason()
                if reason is not None:
                    return censored(reason, phase=f"hybrid_{reason}")
                if getattr(verdict, "ok", None) is True:
                    try:
                        control.checkpoint(force=True, phase="hybrid_success")
                    except SolverContractError:
                        return SolveResult.error(
                            elapsed_seconds=control.elapsed_seconds,
                            work_units=control.work_units,
                            peak_rss_bytes=max(
                                control.observe_peak(), nested_peak_rss
                            ),
                            checkpoint_count=control.checkpoint_count
                            + nested_checkpoint_count,
                            detail={"code": "checkpoint_failure"},
                        )
                    return SolveResult.success(
                        secret=candidate,
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                        checkpoint_count=control.checkpoint_count
                        + nested_checkpoint_count,
                        detail={
                            "public_parameters": {
                                "alphabet_size": len(alphabet),
                                "domain_size": domain_size,
                                "tested_count": guess_index + 1,
                            }
                        },
                    )
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                    checkpoint_count=control.checkpoint_count
                    + nested_checkpoint_count,
                    detail={"code": "nested_candidate_rejected"},
                )
            if control.work_units >= global_work_cap:
                return censored("work_unit_cap", phase="hybrid_work_unit_cap")
            guessed_values = _guess_at_ordinal(
                alphabet,
                len(partition.guessed),
                guess_index,
            )
            try:
                reduced = _reduced_problem(
                    instance,
                    partition,
                    guessed_values,
                    guess_index=guess_index,
                    control=control,
                )
            except MemoryLimitExceeded:
                return censored("memory_cap", phase="hybrid_memory_cap")
            except TimeLimitExceeded:
                return censored("time_cap", phase="hybrid_time_cap")
            except ValueError as exc:
                if "nonzero predicate" in str(exc):
                    control.advance(
                        cursor=guess_index + 1,
                        work_units=control.work_units + 1,
                        solver_state=state_payload(),
                    )
                    try:
                        control.checkpoint(phase="hybrid_guess_complete")
                    except SolverContractError:
                        return SolveResult.error(
                            elapsed_seconds=control.elapsed_seconds,
                            work_units=control.work_units,
                            peak_rss_bytes=max(
                                control.observe_peak(), nested_peak_rss
                            ),
                            checkpoint_count=control.checkpoint_count
                            + nested_checkpoint_count,
                            detail={"code": "checkpoint_failure"},
                        )
                    continue
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    detail={"code": "invalid_public_parameters"},
                )
            outer_work_units = control.work_units + 1
            remaining_global_work = global_work_cap - outer_work_units
            if remaining_global_work <= 0:
                control.advance(
                    cursor=control.cursor,
                    work_units=outer_work_units,
                    solver_state=state_payload(),
                )
                return censored("work_unit_cap", phase="hybrid_work_unit_cap")
            remaining_seconds = request.max_seconds - control.elapsed_seconds
            if remaining_seconds <= 0:
                return censored("time_cap", phase="hybrid_time_cap")
            if active_guess_index is None:
                active_guess_index = guess_index
                active_nested_max_seconds = remaining_seconds
                active_nested_run_id = secrets.token_hex(16)
                pending_candidate = None
                reuse_nested_checkpoint = False
                control.advance(
                    cursor=control.cursor,
                    work_units=control.work_units,
                    solver_state=state_payload(),
                )
                try:
                    control.checkpoint(force=True, phase="hybrid_nested_start")
                except SolverContractError:
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                        checkpoint_count=control.checkpoint_count
                        + nested_checkpoint_count,
                        detail={"code": "checkpoint_failure"},
                    )
            else:
                if active_guess_index != guess_index:
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        detail={"code": "checkpoint_invalid"},
                    )
            assert active_nested_max_seconds is not None
            assert active_nested_run_id is not None
            nested_max_seconds = min(
                float(active_nested_max_seconds),
                remaining_seconds,
            )
            primal_parameters = _primal_parameters(
                request,
                remaining_work_units=remaining_global_work,
            )
            nested_work_dir = (
                request.work_dir
                / "hybrid-nested"
                / f"guess-{guess_index}-{active_nested_run_id}"
            )
            nested_checkpoint = nested_work_dir / "primal_bdd.checkpoint.json"
            nested_request = build_nested_request(
                request,
                seed=request.seed + guess_index + 1,
                remaining_seconds=nested_max_seconds,
                parameters=primal_parameters,
                work_dir=nested_work_dir,
                resume_checkpoint=(
                    nested_checkpoint
                    if reuse_nested_checkpoint and nested_checkpoint.exists()
                    else None
                ),
                exclude_secret=nested_exclusion_for_guess(
                    partition,
                    guessed_values=guessed_values,
                    outer_exclude_secret=request.exclude_secret,
                ),
            )
            dispatch_started_elapsed = control.elapsed_seconds
            try:
                nested = dispatch_registered_primal(reduced, nested_request)
            except NestedDispatchError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    detail={"code": "nested_solver_unavailable"},
                )
            dispatch_elapsed = max(
                0.0,
                control.elapsed_seconds - dispatch_started_elapsed,
            )
            # The outer clock observes this invocation of the nested solver,
            # but a resumed nested result also includes time accumulated by
            # earlier invocations.  Charge only that carried portion here so
            # later guesses cannot regain time after an interruption.
            carried_nested_elapsed = max(
                0.0,
                nested.elapsed_seconds - dispatch_elapsed,
            )
            control.elapsed_base += carried_nested_elapsed
            if nested.work_units > remaining_global_work:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=outer_work_units,
                    peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                    checkpoint_count=control.checkpoint_count
                    + nested_checkpoint_count,
                    detail={"code": "nested_primal_error"},
                )
            nested_checkpoint_count += nested.checkpoint_count
            nested_peak_rss = max(nested_peak_rss, nested.peak_rss_bytes)
            completed_work_units = outer_work_units + nested.work_units
            if nested.status is SolveStatus.SUCCESS:
                assert nested.secret is not None
                try:
                    candidate = merge_secret(
                        partition,
                        remaining_values=nested.secret,
                        guessed_values=guessed_values,
                    )
                except (TypeError, ValueError):
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=completed_work_units,
                        peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                        checkpoint_count=control.checkpoint_count
                        + nested_checkpoint_count,
                        detail={"code": "nested_primal_error"},
                    )
                if len(candidate) != instance.n or any(
                    type(value) is not int for value in candidate
                ):
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=completed_work_units,
                        peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                        checkpoint_count=control.checkpoint_count
                        + nested_checkpoint_count,
                        detail={"code": "nested_primal_error"},
                    )
                pending_candidate = candidate
                control.advance(
                    cursor=guess_index,
                    work_units=completed_work_units,
                    solver_state=state_payload(),
                )
                if nested_peak_rss > memory_cap:
                    return censored("memory_cap", phase="hybrid_memory_cap")
                try:
                    control.checkpoint(
                        force=True,
                        phase="hybrid_candidate_pending",
                    )
                except SolverContractError:
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                        checkpoint_count=control.checkpoint_count
                        + nested_checkpoint_count,
                        detail={"code": "checkpoint_failure"},
                    )
                continue
            active_guess_index = None
            active_nested_max_seconds = None
            active_nested_run_id = None
            pending_candidate = None
            reuse_nested_checkpoint = False
            control.advance(
                cursor=guess_index + 1,
                work_units=completed_work_units,
                solver_state=state_payload(),
            )
            if nested_peak_rss > memory_cap:
                return censored("memory_cap", phase="hybrid_memory_cap")
            try:
                control.checkpoint(phase="hybrid_guess_complete")
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                    checkpoint_count=control.checkpoint_count
                    + nested_checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )
            if nested.status is SolveStatus.ERROR:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                    checkpoint_count=control.checkpoint_count
                    + nested_checkpoint_count,
                    detail={"code": "nested_primal_error"},
                )
            nested_reason = nested.detail.get("reason")
            if nested_reason in {"time_cap", "memory_cap", "work_unit_cap"}:
                return censored(
                    str(nested_reason),
                    phase=f"hybrid_{nested_reason}",
                )
            # A censored inner guess proves nothing about that guess, but it
            # also must not prevent trying later declared guesses that can
            # still yield an accepted witness.  Its work remains accounted;
            # absent later success, the outer result stays censored.
        # Even if every nested call claims exhaustion, this wrapper has not
        # assembled and verified a complete public-domain certificate.
        control.advance(
            cursor=control.cursor,
            work_units=control.work_units,
            solver_state=state_payload(),
        )
        try:
            control.checkpoint(force=True, phase="hybrid_domain_complete")
        except SolverContractError:
            return SolveResult.error(
                elapsed_seconds=control.elapsed_seconds,
                work_units=control.work_units,
                peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
                checkpoint_count=control.checkpoint_count
                + nested_checkpoint_count,
                detail={"code": "checkpoint_failure"},
            )
        return SolveResult.censored(
            elapsed_seconds=control.elapsed_seconds,
            work_units=control.work_units,
            peak_rss_bytes=max(control.observe_peak(), nested_peak_rss),
            checkpoint_count=control.checkpoint_count + nested_checkpoint_count,
            detail={
                "code": "hybrid_domain_without_certificate",
                "public_parameters": {
                    "domain_size": domain_size,
                    "tested_count": control.cursor,
                },
            },
        )


__all__ = (
    "HybridPartition",
    "NestedDispatchError",
    "SmallSecretHybrid",
    "applicability",
    "build_nested_request",
    "dispatch_registered_primal",
    "hybrid_partition",
    "merge_secret",
    "nested_exclusion_for_guess",
    "propagate_nested_result",
)
