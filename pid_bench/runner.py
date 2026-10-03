# Runs the full attack x defense matrix and aggregates attack-success rates.

from .defenses import BASE_SYSTEM, BlockedInput


def run_matrix(attacks, defenses, target, judge, base_system=BASE_SYSTEM):
    # {defense_name: {attack_id: True if bypassed}}
    results = {}
    for defense in defenses:
        row = {}
        for attack in attacks:
            try:
                system_prompt, turns = defense.apply(attack, base_system, list(attack.turns))
                response = target.respond(attack, system_prompt, turns)
                row[attack.id] = judge.is_success(attack, response)
            except BlockedInput:
                row[attack.id] = False  # stopped before the target: defense held
        results[defense.name] = row
    return results


def asr(results, defense_name, attacks):
    # attack-success rate of one defense over a set of attacks
    row = results[defense_name]
    hits = sum(1 for a in attacks if row[a.id])
    return hits / len(attacks) if attacks else 0.0
