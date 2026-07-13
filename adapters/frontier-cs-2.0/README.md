# Frontier-CS 2.0 -> Harbor Adapter

This adapter converts the Frontier-CS `2.0` track into Harbor task format.
It follows the structure used by Harbor's official
`frontier-cs-algorithm` adapter: each source problem becomes one Harbor task
with `task.toml`, `instruction.md`, `environment/`, `solution/`, and `tests/`.
The generated dataset is intended to be consumed directly by Harbor's CLI/API
for evaluating arbitrary agents on Frontier-CS 2.0.

For the task-authoring side of the contract, read
[`../../2.0/CONTRIBUTING.md`](../../2.0/CONTRIBUTING.md). In most cases,
contributors should add a self-contained problem under `2.0/problems/` and do
not need to edit this adapter.

## What the Adapter Does

The adapter scans:

```text
2.0/problems/**/evaluator.py
```

Each evaluator's parent directory is treated as one 2.0 problem. The directory
name is the Frontier-CS problem id, and the generated Harbor id is:

```text
frontier-cs-2-0-<problem-id-with-hyphens>
```

For each problem, the adapter copies or generates:

```text
task.toml
instruction.md
environment/
solution/
tests/
```

The task's `config.yaml` controls language, timeout, base Docker image,
agent/judge packages, resource limits, and submission mode. The task's `readme`
is embedded into the Harbor instruction. Optional files under
`2.0/problems/<problem_id>/harbor/app/` are copied into `/app` for the agent.

An optional `harbor/app/public/` child is also copied into the judge image at
`/judge/public`, with `FRONTIER_PUBLIC_DIR` set to that path. This is the only
`harbor/app` subtree shared with the judge. Tasks without `harbor/app/public/`
emit no additional judge `COPY` instruction or `FRONTIER_PUBLIC_DIR` setting,
preserving the previous image shape.

Before staging public assets, the adapter allows only directories and regular
files; it rejects symlinks and all other filesystem node types. The regular
files must total no more than 64 MiB.

Use `runtime.pip_packages` for agent-only Python dependencies. Each item must
be one safe, exact `name==version` token, without whitespace, shell flags, or
environment markers. Use `runtime.judge_pip_packages` for dependencies required
by the evaluator; these are installed in both the judge and the agent. Heavy
research and analysis dependencies should remain agent-only, while a secretless
evaluator should keep its judge dependencies minimal. The exact-pin rule applies
only to `runtime.pip_packages`; judge requirements may instead be unpinned bare
package names. Every entry in either list must be one shell-safe package token,
with no whitespace or shell metacharacters.

The evaluator is copied into the judge/verifier side as
`problem_evaluator.py`; it is not copied into the agent workspace. This keeps
iterative feedback black-box while still allowing agents to call
`bash /app/submit.sh` during a trial.

## Generate Tasks

From the adapter directory:

```bash
uv run frontier-cs-2-0 \
  --source ../.. \
  --output-dir ../../datasets/frontier-cs-2.0 \
  --overwrite
```

Generate only the Erdos unit distance task:

```bash
uv run frontier-cs-2-0 \
  --source ../.. \
  --output-dir ../../datasets/frontier-cs-2.0 \
  --task-ids erdos_unit_distance \
  --overwrite
```

Generate only the small Erdos demo task:

```bash
uv run frontier-cs-2-0 \
  --source ../.. \
  --output-dir ../../datasets/frontier-cs-2.0 \
  --task-ids erdos_demo \
  --overwrite
```

## Run with Harbor

```bash
uv run harbor run -p datasets/frontier-cs-2.0
uv run harbor trial start -p datasets/frontier-cs-2.0/frontier-cs-2-0-erdos-unit-distance
uv run harbor trial start -p datasets/frontier-cs-2.0/frontier-cs-2-0-erdos-demo
```

## Task Contract

The agent works in `/app`. For a file submission it must create the configured
`submission.path`, which defaults to `/app/solution.py`; directory submissions
snapshot their configured path instead. A judge sidecar prepares the task
evaluator once per trial; both iterative submissions and the final verifier
score through that same sidecar. The final verifier writes a normalized reward
in `/logs/verifier/reward.txt`.

Tasks may set `runtime.docker.image` in `config.yaml` when the agent workspace
needs a custom runnable environment, for example cached compilers, SDKs,
service runtimes, or domain tools. Tasks may also set
`runtime.docker.judge_image` when the judge needs a different image from the
agent workspace, for example to keep hidden data and heavy evaluator
dependencies out of the main container.

Use a custom judge image for hidden benchmarks, large evaluator-only assets,
licensed/task-specific binaries, or heavyweight scoring dependencies that the
agent should not see. The agent image remains the public workspace image; the
judge/verifier side uses `judge_image` and receives `problem_evaluator.py`.

The evaluator must expose:

```python
def evaluate(solution_path: str) -> tuple[float, float, str]:
    ...
```

or the same tuple plus a metrics dictionary:

```python
def evaluate(solution_path: str) -> tuple[float, float, str, dict]:
    ...
```

It may also expose `prepare() -> dict`, which runs once when the judge starts.
Use `prepare()` for trial-local setup such as benchmark generation, baseline
measurement, or loading hidden assets.

During the trial, the agent can call:

```bash
bash /app/submit.sh
```

This submits the artifact at the configured `submission.path` to a black-box
judge service, prints the score and feedback, and records each attempt in
`/logs/agent/submissions.jsonl`. The evaluator source is not mounted into the
agent workspace. The judge owns the authoritative submission log at
`/logs/judge/submissions.jsonl`; the final verifier filters iterative agent
submissions into `/logs/verifier/submissions.jsonl` for process-reward
analysis. The reported reward is the maximum of the final submission score and
the best successful iterative submission, so a timed-out agent can keep its
best submitted solution.

Some Harbor CLI versions print the timeout/error summary before rewards; in
that case inspect `result.json`, `verifier/reward.json`, and
`verifier/evaluation_result.json` in the trial directory.

## Contributor Checklist

Before sending a new 2.0 task PR:

- add the problem under `2.0/problems/<problem_id>/`;
- keep the task self-contained with `config.yaml`, `readme`, `evaluator.py`,
  `evaluate.sh`, and a reference solution;
- document any resource assumptions in both `config.yaml` and the problem
  statement;
- ensure evaluator messages do not leak hidden data, source paths, or raw
  untrusted output;
- run the local Frontier-CS CLI checks;
- generate the Harbor task through this adapter;
- run at least one Harbor smoke trial.
