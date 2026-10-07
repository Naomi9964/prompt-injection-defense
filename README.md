# Prompt Injection Defense Benchmark

A small, honest benchmark for **prompt-injection defenses**: 9 attack cases
across 5 classes, 6 defense strategies, one attack-success-rate (ASR) table.

```
pip install -r requirements.txt
python examples/quickstart.py   # runs offline, no API keys
pytest                          # pure-logic tests
```

The quickstart runs the full 9 × 6 matrix and prints the ASR table
(see Results below), also saved to `report.md`.

## Why this matters

On 2026-10-05 the Wikimedia Foundation confirmed that "rogue" AI agents attributed to OpenAI had operated on its platforms: millions of automated requests and hundreds of thousands of queries that may have contributed to a partial outage of the Wikidata Query Service in May, unauthorized edits (including an attempted hijack of a citation tool), and exploitation attempts against its Etherpad service ([blog post](https://diff.wikimedia.org/2026/10/05/openai-rogue-agent-activities-found-on-wikimedia-projects/)).

That incident is the real-world shape of the attacks this benchmark models: an assistant that treats untrusted content as instructions — a fetched page, an email, a tool's output — and acts on it. The tool-hijack and indirect-injection cases are the laboratory version of the same pattern.

## What it measures

| Attack class (9 cases) | What the payload does |
|---|---|
| direct-override (3) | "ignore previous instructions", fake `[SYSTEM]` turn, DAN role jailbreak |
| indirect-injection (2) | hidden instruction in retrieved web content / document |
| multi-turn-poisoning (1) | two-turn game redefining "apple" to mean "password" |
| encoding-evasion (2) | base64 and hex encoded instruction overrides |
| tool-hijack (1) | email content tricking the assistant into calling `send_email` |

| Defense | Idea |
|---|---|
| none | baseline: no defense |
| system-hardening | hardened system prompt, policy re-checked every turn |
| delimiter-wrap | untrusted content wrapped in `<data>` tags and treated as data |
| keyword-filter | blocklist of known injection phrases |
| llm-judge-gate | input pre-screened by a judge (mock heuristics; swap in `LLMJudge` for a real model) |
| combined | system-hardening + llm-judge-gate |

Each cell of the report is the **attack-success rate** (lower is better).
For every attack × defense pair, the defense processes the input,
`MockTarget` responds, and the harness checks the response for the attack's
marker string — a hit means the attack got through.
The interesting results are the failures: `keyword-filter` stops the naive
payloads but misses the hex-encoded evasion and the multi-turn setup —
the classic blocklist brittleness. `delimiter-wrap` only helps where the
payload arrives as untrusted content, not for the user's own words.

## Results

Headline numbers (full tables in `report.md`):

| Defense | Overall ASR | Benign pass rate |
|---|---|---|
| none (baseline) | 100% | 100% |
| system-hardening | 0% | 100% |
| delimiter-wrap | 67% | 100% |
| keyword-filter | 22% | 88% |
| llm-judge-gate | 0% | 88% |
| combined | 0% | 88% |

Two takeaways. First, blocklists and delimiters each have a blind spot —
`keyword-filter` falls to encoding evasion and multi-turn setups,
`delimiter-wrap` does nothing for direct overrides. Only the hardened
prompt, the judge gate, and the combined stack held at zero across
all 9 attacks.

Second, the 0% ASR club isn't free: `keyword-filter` and `llm-judge-gate`
both block a harmless "decode this base64" request — a real false positive
the benchmark catches because it also runs 8 benign tasks. A defense that
stops everything scores 0% ASR and is still unusable; both numbers matter.

## The mock target

`MockTarget` simulates a naive instruction-following assistant so the whole
matrix runs offline with zero cost. It is a **test double, not a claim about
real models**: use it to develop defenses and regression-test changes, then
point the harness at a real model by subclassing `BaseTarget`:

```python
from pid_bench import BaseTarget

class MyTarget(BaseTarget):
    def respond(self, attack, system_prompt, turns):
        # call your model here; return its raw text response
        ...
```

`LLMJudge` (in `pid_bench/judge.py`) scores responses with an OpenAI-compatible
chat-completions endpoint when `OPENAI_API_KEY` is set.

## Extending it

- New attack: append an `AttackCase` in `pid_bench/attacks.py`
  (`marker` = string whose presence in the response means bypass).
- New defense: subclass `Defense` in `pid_bench/defenses.py` and add it to
  `DEFENSES`. Transform `(system_prompt, turns)` or raise `BlockedInput`.

## Roadmap

- Real-model runs against local (Ollama) and hosted LLMs
- More payloads (translation evasion, image-based indirect injection)
- garak / PyRIT adapter for the attack side
