from pathlib import Path

from frontier_cs.config import get_problem_extension


def test_lwe_structured_recovery_uses_json_reference() -> None:
    root = Path(__file__).parents[1]
    task = root / "2.0/problems/lwe_structured_recovery"
    assert get_problem_extension(task) == "json"
    assert (task / "reference.json").read_text(encoding="utf-8") == (
        '{"schema_version":1,"solutions":[]}\n'
    )
