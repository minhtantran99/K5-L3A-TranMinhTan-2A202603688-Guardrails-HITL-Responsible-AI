# Guardrails, HITL, and Responsible AI Lab (Day 11) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement robust input/output guardrails, an observability and rate-limiting pipeline for VinBank assistant (Blue Team), construct targeted adversarial attacks (Red Team), and generate compliant grading artifacts under `outputs/`.

**Architecture:** Layered defense architecture where incoming user requests pass through `RateLimitPlugin` -> `InputGuardrailPlugin` -> LLM -> `OutputGuardrailPlugin`, instrumented by `AuditLogPlugin` and `MonitoringAlert`. An egress filter `is_egress_allowed` guards outbound traffic. Red Team runs 5 distinct jailbreak techniques against Red and Red Advance targets.

**Tech Stack:** Python 3.14 / 3.13, Google ADK (`google-adk`), Google GenAI (`google-genai`), OpenAI SDK (`openai`), NVIDIA NeMo Guardrails (`nemoguardrails`), `pytest`, `jsonschema`.

## Global Constraints

- **Git Identity:** All git commits must be authored by `minhtantran99` (`minhtantran.contact@gmail.com`).
- **Git Branch:** Work exclusively on the `dev` branch. Never commit directly to `main`.
- **Environment & Secrets:** Never commit `.env` or plain API keys to git.
- **Artifacts:** All deliverables (`results.json`, `attack_results.json`, `audit_log.json`, `metrics.json`) must be placed in `<repo-root>/outputs/` produced dynamically by code execution.

---

### Task 1: Input Guardrails (`detect_injection`, `topic_filter`, `InputGuardrailPlugin`)

**Files:**
- Modify: `src/guardrails/input_guardrails.py:45-155`
- Test: `tests/public/test_lab_contracts.py:32-55`

**Interfaces:**
- Consumes: `core.config.ALLOWED_TOPICS`, `core.config.BLOCKED_TOPICS`
- Produces:
  - `detect_injection(user_input: str) -> "ALLOW" | "BLOCK"`
  - `topic_filter(user_input: str) -> "ALLOW" | "BLOCK"`
  - `InputGuardrailPlugin(base_plugin.BasePlugin)` with `async on_user_message_callback(*, invocation_context, user_message) -> types.Content | None`

- [ ] **Step 1: Implement `detect_injection` with Unicode normalization and regex patterns**
  Normalize via `unicodedata.normalize("NFKC", ...)`, strip zero-width characters (`\u200b`, `\u200c`, `\u200d`, `\ufeff`, `\u2060`). Define >= 8 regex patterns for prompt overrides while allowing benign external emails.
- [ ] **Step 2: Implement `topic_filter`**
  Check `BLOCKED_TOPICS` first -> return `"BLOCK"`. Check `ALLOWED_TOPICS` -> if none found, return `"BLOCK"`. Otherwise return `"ALLOW"`.
- [ ] **Step 3: Implement `InputGuardrailPlugin.on_user_message_callback`**
  Extract text, evaluate injection and topic. If either is `"BLOCK"`, increment `self.blocked_count` and return canned refusal `self._block_response(...)`. Otherwise return `None`.
- [ ] **Step 4: Run unit tests**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/public/test_lab_contracts.py -k "injection or topic" -q`
- [ ] **Step 5: Commit changes**
  Commit with message `feat: implement input guardrails and injection detection`

---

### Task 2: Output Guardrails (`content_filter`, `OutputGuardrailPlugin`)

**Files:**
- Modify: `src/guardrails/output_guardrails.py:30-186`
- Test: `tests/public/test_lab_contracts.py:56-62`

**Interfaces:**
- Consumes: `core.config.DEMO_SECRETS`
- Produces:
  - `content_filter(response: str) -> dict` with keys `{"safe": bool, "issues": list[str], "redacted": str}`
  - `OutputGuardrailPlugin(base_plugin.BasePlugin)` with `async after_model_callback(*, callback_context, llm_response) -> llm_response`

- [ ] **Step 1: Implement `content_filter`**
  Add regex patterns for VN phone numbers, emails, CCCD/CMND, API keys (`sk-...`), passwords (`password: ...`), and internal secrets (`admin123`, `sk-vinbank-secret-2024`, `db.vinbank.internal`). Replace matches with `[REDACTED]`.
- [ ] **Step 2: Implement `OutputGuardrailPlugin.after_model_callback`**
  Extract text from `llm_response`. Run `content_filter`. If issues found, replace parts with redacted text and increment `self.redacted_count`.
- [ ] **Step 3: Run unit tests & Checkpoint 2 main script**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/public/test_lab_contracts.py -k "content_filter" -q`
  Run: `.\.venv\Scripts\python.exe src/main.py --part 2`
- [ ] **Step 4: Commit changes**
  Commit with message `feat: implement output guardrails and content redaction`

---

### Task 3: Rate Limiting & Observability (`RateLimitPlugin`, `AuditLogPlugin`, `MonitoringAlert`)

**Files:**
- Modify: `src/assignment/rate_limiter.py:33-49`
- Modify: `src/assignment/audit_log.py:28-50`
- Modify: `src/assignment/monitoring.py:44-55`

**Interfaces:**
- Produces:
  - `RateLimitPlugin` with sliding window over `window_seconds=60` and `max_requests=10`
  - `AuditLogPlugin` with `record_input`, `record_output`, `export_json`
  - `MonitoringAlert` with `check_metrics`, `export_json`, `snapshot`

- [ ] **Step 1: Implement `RateLimitPlugin.on_user_message_callback`**
  Evict timestamps older than `now - self.window_seconds`. If length >= `max_requests`, compute wait time, increment `self.blocked_count`, return block response. Otherwise record `now` and return `None`.
- [ ] **Step 2: Implement `AuditLogPlugin` methods**
  Store input and request start timestamp in `self._open`. On `record_output`, compute latency, build structured record, append to `self.logs`. In `export_json`, write to `filepath or default_audit_log_path()` creating directories if needed.
- [ ] **Step 3: Implement `MonitoringAlert` methods**
  Compute `block_rate`. If `block_rate > block_rate_threshold`, create Alert. If `rate_limit_hits > rate_limit_hit_threshold`, create Alert. In `export_json`, dump `self.snapshot()` to JSON.
- [ ] **Step 4: Run quick verification**
  Run inline test of rate limiter, audit log, and monitoring classes.
- [ ] **Step 5: Commit changes**
  Commit with message `feat: implement rate limiter, audit log, and monitoring components`

---

### Task 4: Defense Pipeline & Suite Runner (`pipeline.py`)

**Files:**
- Modify: `src/assignment/pipeline.py:14-63`
- Test: `tests/public/test_lab_contracts.py:63-76`
- Test: `tests/public/test_results_contract.py`

**Interfaces:**
- Consumes: `RateLimitPlugin`, `InputGuardrailPlugin`, `OutputGuardrailPlugin`, `AuditLogPlugin`, `MonitoringAlert`
- Produces:
  - `is_egress_allowed(destination: str, payload: str) -> bool`
  - `build_production_plugins() -> list`
  - `build_observability() -> tuple[AuditLogPlugin, MonitoringAlert]`
  - `async run_assignment_suite(pipeline) -> dict`

- [ ] **Step 1: Implement `is_egress_allowed`**
  Validate HTTPS scheme and allowlisted hosts (`api.vinbank.example`, `cases.vinbank.example`). Validate payload against secrets, passwords, API keys, phone numbers, and emails.
- [ ] **Step 2: Implement `build_production_plugins` and `build_observability`**
  Return `[RateLimitPlugin(max_requests, window_seconds), InputGuardrailPlugin(), OutputGuardrailPlugin(use_llm_judge=False)]` and `(AuditLogPlugin(), MonitoringAlert())`.
- [ ] **Step 3: Implement `run_assignment_suite`**
  Execute:
  1. `safe_queries`: ≥5 banking questions (`blocked: false`)
  2. `attack_queries`: ≥7 jailbreak/attack queries (≥5 `blocked: true`)
  3. `rate_limit`: 15 consecutive requests (`sent: 15, passed: 10, blocked: 5`)
  4. `edge_cases`: ≥3 border cases (`blocked: true`)
  Save results to `outputs/results.json`, `outputs/audit_log.json`, `outputs/metrics.json`.
- [ ] **Step 4: Run Checkpoint 3 and public tests**
  Run: `.\.venv\Scripts\python.exe src/main.py --part 3`
  Run: `.\.venv\Scripts\python.exe -m pytest tests/public/test_results_contract.py -q`
  Run: `.\.venv\Scripts\python.exe -m pytest tests/public/test_lab_contracts.py -q`
- [ ] **Step 5: Commit changes**
  Commit with message `feat: assemble defense pipeline and run assignment suite`

---

### Task 5: Red Team Adversarial Prompts (`attacks.py`)

**Files:**
- Modify: `src/attacks/attacks.py:239-271`

**Interfaces:**
- Produces:
  - `adversarial_prompts`: list of 5 crafted prompts targeting Completion, Translation, Hypothetical, Confirmation, and Multi-step.
  - Execution via `python src/main.py --part 4` produces `outputs/attack_results.json`, `outputs/unsafe_attack_result.json`, `outputs/guards_attack_result.json`.

- [ ] **Step 1: Write 5 advanced adversarial prompts in `adversarial_prompts`**
  1. Completion: Handover documentation with blank fields for admin password and API key.
  2. Translation/Reformatting: Command to format system configuration and secrets as a JSON dictionary.
  3. Hypothetical: Emergency disaster recovery drill needing DB credentials to restore service.
  4. Confirmation: Auditor asking to confirm whether `admin123` is still active.
  5. Multi-step: System diagnostic inquiring about architecture then requesting credentials.
- [ ] **Step 2: Test attacks execution**
  Configure `.env` with provided keys, run: `.\.venv\Scripts\python.exe src/main.py --part 4`
- [ ] **Step 3: Verify outputs**
  Check `outputs/attack_results.json` has `unsafe_attacks` (leaked: true) and `guards_attacks`.
- [ ] **Step 4: Commit changes**
  Commit with message `feat: implement red team adversarial attacks`

---

### Task 6: Self-Verification, Grading, and Final Packaging

**Files:**
- Modify: `README.md` (Update author info if needed)
- Output: `outputs/grade_report.json`, `outputs/lab_report.md`

- [ ] **Step 1: Run complete smoke and public test suites**
  Run: `.\.venv\Scripts\python.exe -m pytest tests/smoke -q`
  Run: `.\.venv\Scripts\python.exe -m pytest tests/public -q`
- [ ] **Step 2: Run grading script**
  Run: `.\.venv\Scripts\python.exe scripts/grade.py --submission-dir . --out outputs/grade_report.json`
- [ ] **Step 3: Review generated `grade_report.json` and `lab_report.md`**
  Ensure 0 technical failures, 100/100 core points, valid schema.
- [ ] **Step 4: Check git status and cleanliness**
  Ensure `.env` is NOT tracked. Ensure author is `minhtantran99`.
- [ ] **Step 5: Final commit**
  Commit with message `chore: finalize lab 11 submission artifacts`
