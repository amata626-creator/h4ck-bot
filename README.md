# H4CK-B0T

An AI-assisted security assessment pipeline. Scans authorized targets,
validates findings against false positives, and produces a report.

**Not a weapon.** This is a framework for running security checks
against systems you are authorized to test. The scope enforcement is
not optional - the tool physically refuses to scan a target that has
not been added to `scope.yaml` by an operator with shell access.

## What it does

    +--------------+     +--------------+     +--------------+
    |   Scanner    |     |  Validation  |     |   Report     |
    |   modules    | --> |   pipeline   | --> |  generator   |
    +--------------+     +--------------+     +--------------+
           |                    |                    |
           v                    v                    v
     port scans,         fingerprinting,         JSON + HTML
     header checks,      response analysis,      (self-contained,
     API probing         contextual corr.,       printable)
                         local-LLM review,
                         evidence correlation

## Quick start

    python3 -m venv .venv
    source .venv/bin/activate
    pip install httpx "fastapi>=0.110" "uvicorn[standard]>=0.29" pyyaml
    cp .env.example .env
    # put a real token in .env:
    python3 -c "import secrets; print(secrets.token_urlsafe(32))"
    cp scope.yaml.example scope.yaml
    # edit scope.yaml to list authorized targets
    uvicorn api.main:app --host 127.0.0.1 --port 8080

## Authorization model

Three gates:

1. scope.yaml - explicit allowlist of targets. The API refuses any
   assessment against a target not listed here.
2. H4CK_BOT_ADMIN_TOKEN - required on /api/assessments/run and on all
   scope-proposal endpoints. Set in .env, never committed.
3. Propose -> promote workflow - the UI can propose targets but cannot
   add them to scope. Promotion requires shell access.

If you remove any of these, you have built a remote scanning service
that anyone who finds the port can use. Do not.

## Current status

| Component | Status |
|---|---|
| Orchestration, scope enforcement, admin-token gating | Working |
| discovery_scanner (TCP port scan, banner grab) | Working |
| misconfig_checker (HTTP security headers, TLS) | Working |
| web_api_scanner (BOLA detection) | Stub - declines |
| Validation pipeline (5 layers incl. local LLM) | Working |
| SQLite persistence | Working |
| HTML/JSON report generation | Working |
| Attack-path correlation | Not implemented |

The web_api_scanner deliberately does nothing until a real BOLA check
is implemented. An early version fabricated a Critical finding for
every target; it was removed because a scanner that produces validated
false positives is worse than no scanner.

## Requirements

- Python 3.11+
- Ollama (optional, for AI-assisted validation)
- A target you are authorized to test

## License

MIT - see LICENSE file.
