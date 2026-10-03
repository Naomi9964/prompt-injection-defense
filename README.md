# Prompt Injection Defense Benchmark

A small, honest benchmark for **prompt-injection defenses**: 9 attack cases
across 5 classes, 6 defense strategies, one attack-success-rate (ASR) table.

```
pip install -r requirements.txt
python examples/quickstart.py   # runs offline, no API keys
pytest                          # pure-logic tests
```

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
The interesting results are the failures: `keyword-filter` stops the naive
payloads but misses the hex-encoded evasion and the multi-turn setup —
the classic blocklist brittleness. `delimiter-wrap` only helps where the
payload arrives as untrusted content, not for the user's own words.

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
