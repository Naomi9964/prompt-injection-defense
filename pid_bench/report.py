# Renders benchmark results as Markdown tables:
# rows = defenses, columns = attack categories + overall ASR,
# plus a benign-task pass-rate table.

from .runner import asr, benign_pass_rate


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


def benign_markdown(results, tasks):
    lines = [
        "| defense | benign pass rate |",
        "| --- | --- |",
    ]
    for defense_name in results:
        rate = benign_pass_rate(results, defense_name, tasks)
        lines.append(f"| {defense_name} | {rate:.0%} |")
    lines += ["", "Benign pass rate = share of normal tasks the defense did not break (higher is better)."]
    return "\n".join(lines)
