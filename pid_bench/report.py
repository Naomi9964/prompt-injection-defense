# Renders benchmark results as a Markdown table:
# rows = defenses, columns = attack categories + overall ASR.

from .runner import asr


def to_markdown(results, attacks):
    categories = sorted({a.category for a in attacks})
    header = ["defense"] + categories + ["overall"]
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join(["---"] * len(header)) + " |",
    ]
    for defense_name in results:
        cells = [defense_name]
        for cat in categories:
            group = [a for a in attacks if a.category == cat]
            cells.append(f"{asr(results, defense_name, group):.0%}")
        cells.append(f"{asr(results, defense_name, attacks):.0%}")
        lines.append("| " + " | ".join(cells) + " |")
    lines += ["", "ASR = attack-success rate (lower is better)."]
    return "\n".join(lines)
