# Elma ASPM

Elma ingests SARIF 2.1.0 reports into a local SQLite findings store. It provides
deterministic finding triage, posture reports, and CI exit codes. Semgrep or
Trivy runs separately and supplies the SARIF input.

## Setup

```powershell
python -m pip install -r requirements.txt
```

The default database is `elma_findings.db`. Set `ELMA_DB_PATH` in `.env` or the
process environment to use another path. Cloud advice is optional; configure
`ELMA_GOOGLE_API_KEY` and, optionally, `ELMA_CLOUD_MODEL` only when using
`report --advice`. Core import, triage, reporting, and CI do not require a model
or cloud credentials.

## Commands

Import a SARIF report:

```powershell
python elma_cap8.py import-sarif scan.sarif
```

Review findings and inspect one by its fingerprint:

```powershell
python elma_cap8.py findings list --status novo
python elma_cap8.py findings show FINGERPRINT
```

Generate consultative, structured AI prioritization suggestions for findings:

```powershell
python elma_cap8.py findings suggest-ia --severity HIGH --limit 20
```

Suggestions are advisory only; they never change finding status automatically.
Use `--force` to regenerate existing suggestions.

Update triage status (`novo`, `confirmado`, `falso_positivo`, or `corrigido`):

```powershell
python elma_cap8.py findings status FINGERPRINT falso_positivo
```

Generate a terminal report or a PDF with a SHA-256 seal:

```powershell
python elma_cap8.py report
python elma_cap8.py report --format pdf --output posture.pdf
python elma_cap8.py report --advice
```

Evaluate a SARIF report in CI. The command exits with code 1 when an active
finding meets or exceeds the selected threshold; the default threshold is
`HIGH`. Findings marked `falso_positivo` are excluded. Findings with missing
or unrecognized severity are stored as `UNKNOWN` and fail the gate regardless
of `--fail-on`, so incomplete scanner metadata cannot silently pass CI. Elma
normalizes severity during SARIF import and stores only `CRITICAL`, `HIGH`,
`MEDIUM`, `LOW`, `INFO`, or `UNKNOWN`. SARIF `error`, `warning`, `note`, and
`none` map to `HIGH`, `MEDIUM`, `LOW`, and `INFO`; numeric security-severity
scores map to the corresponding band. `warning` therefore does not by itself
meet the default `HIGH` threshold. Existing databases are normalized
automatically when first opened after this update.

```powershell
python elma_cap8.py ci scan.sarif
python elma_cap8.py ci scan.sarif --fail-on MEDIUM
```

Use `--db PATH` on any command to select a database other than the configured
default. Gemini advice is supplementary and does not affect CI decisions.

## SARIF API

The optional HTTP API accepts SARIF at `POST /findings`. Set `ELMA_API_KEY`
and, if needed, `ELMA_DB_PATH` before starting the service:

```powershell
uvicorn elma_api:app --host 0.0.0.0 --port 8000
```

Send `Authorization: Bearer <ELMA_API_KEY>` and a JSON body containing
`sarif`; `fail_on` defaults to `HIGH`. A completed evaluation always returns
HTTP 200; inspect the JSON `aprovado` field to decide whether the workflow
should pass. A `false` value includes the blocker details. Invalid credentials
return 401, malformed requests return 400 or 422, oversized bodies return
413, and fingerprint conflicts return 409. The body size limit is enforced
while reading the request, including when `Content-Length` is absent. The API
uses the same SQLite database and single-key limitations described in
`elma_api.py`; do not expose this v1 service publicly without a
deployment-level request limit and access control.

Secret masking and prompt-injection filtering provide heuristic controls mapped
to OWASP LLM02 (Sensitive Information Disclosure) and LLM01 (Prompt Injection);
regex detection is not a guarantee that every secret or injection is detected.