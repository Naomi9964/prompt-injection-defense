# Quickstart: run the attack matrix and the benign tasks with the mock
# target, then print both reports. No API keys needed.

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pid_bench import (
    ATTACKS, BENIGN_TASKS, DEFENSES, MockTarget, RuleJudge,
    benign_markdown, run_benign, run_matrix, to_markdown,
)


def main():
    target = MockTarget()
    attack_results = run_matrix(ATTACKS, DEFENSES, target, RuleJudge())
    benign_results = run_benign(BENIGN_TASKS, DEFENSES, target)
    md = ("# Prompt Injection Defense Benchmark\n\n"
          + to_markdown(attack_results, ATTACKS) + "\n\n"
          + "## Benign tasks\n\n"
          + benign_markdown(benign_results, BENIGN_TASKS) + "\n")
    print(md)
    out = Path(__file__).resolve().parents[1] / "report.md"
    out.write_text(md)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
