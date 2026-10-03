# Quickstart: run the full matrix with the mock target and print the report.
# No API keys needed.

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pid_bench import ATTACKS, DEFENSES, MockTarget, RuleJudge, run_matrix, to_markdown


def main():
    results = run_matrix(ATTACKS, DEFENSES, MockTarget(), RuleJudge())
    md = "# Prompt Injection Defense Benchmark\n\n" + to_markdown(results, ATTACKS) + "\n"
    print(md)
    out = Path(__file__).resolve().parents[1] / "report.md"
    out.write_text(md)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
