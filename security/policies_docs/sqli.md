# SQL Injection Policy

The SQLi policy inspects string values recursively in MCP `tools/call` arguments before payload-model scoring. It complements path-traversal and shell checks; a high SQLi finding blocks before the model runs. SQLi analysis failures and deadline expiry fail closed.

## Modes

- `none`: SQL-like input is treated as suspicious. Findings are structure-based; isolated words such as `select` or `union` do not trigger a match.
- `query_tool`: SQL is expected. Normal read queries are allowed; tautologies, stacked statements, destructive statements, time delays, catalog probing, dangerous functions, and read-only violations are checked.
- `readonly`: SELECT-only. Writes, DDL, execution statements, CTE/PRAGMA forms, and stacked statements are blocked.

Built-in modes default `db/query` to `readonly`, and `database/query` and `sql/query` to `query_tool`. Global per-tool overrides are available through the admin API. An agent can further override a tool mode through `sql_mode_overrides` in MCP agent metadata. Metadata `role: "read_only"` or `role: "readonly"` forces `readonly`. Per-agent `sqli_allowlist` entries suppress only the matching indicator for that agent and are audit logged.

## Indicators

The editable catalog is `security/sqli_indicators.json`; IDs and default severities are:

| ID | Indicator | Default severity |
| --- | --- | --- |
| SQLI-001 | Tautology | High |
| SQLI-002 | Comment truncation | Medium |
| SQLI-003 | UNION-based injection | High |
| SQLI-004 | Stacked query | High |
| SQLI-005 | Destructive statement | High |
| SQLI-006 | Time-based blind SQLi | High |
| SQLI-007 | Error-based SQLi | Medium |
| SQLI-008 | Schema probing | High |
| SQLI-009 | Boolean-blind probing | Medium |
| SQLI-010 | Dangerous database function | High |
| SQLI-011 | Encoding evasion | Medium |
| SQLI-012 | Quote anomaly | Low |
| SQLI-013 | SQL keyword density | Low |
| SQLI-014 | Read-only mode violation | High |
| SQLI-015 | Oversized input | Low |

Each catalog entry has an ID, description, category, recommendation, severity and either bounded precompiled patterns or a named matcher. To add an indicator, add a catalog entry, implement a bounded matcher if required, add positive/evasion/negative fixtures to `tests/fixtures/sqli_cases.json`, and cover behavior in `tests/policy/test_sqli.py`.

## Decisions And Event Data

- Any High finding blocks.
- Two or more distinct Medium findings block; one Medium flags.
- Low-only findings are logged and allowed.
- Combined risk is `1 - product(1 - severity_weight)`, with weights High `0.9`, Medium `0.5`, Low `0.2`.
- Rule blocks happen before model scoring. The event records `sqli_findings`, `rule_risk_score`, `decision_source`, the redacted payload analysis and SQL-derived model features (`category_counts`, `max_severity`, `keyword_density`). No saved model is changed.
- Evidence is capped at 120 characters and credential-like values are redacted. Findings retain a nested `field_path` such as `arguments.query.filter[1]`.

## API And Audit

- `GET /api/policies/sqli/indicators` requires `gateway:read`.
- `POST /api/policies/sqli/test` requires `gateway:read` and accepts `payload`, `sql_mode`, and optional `tool_name`.
- `PUT /api/policies/sqli/indicators/{id}` changes `enabled` and/or `severity`; requires `gateway:admin`.
- `PUT /api/policies/sqli/tools/{tool_name}/mode?sql_mode=...` configures a global tool mode; requires `gateway:admin`.
- Agent mode/allowlist changes use the existing admin-only MCP agent API and write `AuditLog` entries.

## Limits And Validation

Inputs are capped to 10,000 analyzed characters per string, 256 strings and nesting depth 32. URL decoding is repeated at most three times; zero-width characters, NFKC, comments, hex literals and CHAR/CHR forms are normalized for matching. The per-call analysis budget is 100 ms, below the MCP evaluator's 250 ms deadline.

No SQL-query dataset is present in this repository's `machine_learning/data/` directory. The UNSW-NB15 files label network flows with binary `label` and broad `attack_cat`; they do not contain SQL text or a SQLi-specific ground-truth label. Therefore detection rate, false-positive rate, and sample-level misses/false positives on a labeled SQL corpus are not measurable from the current data. The hand-written fixture suite under `security/tests/` is the available behavioral validation; do not interpret its pass rate as a dataset benchmark.
