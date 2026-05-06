# CyberBoxDefense

CyberBoxDefense is a local MSc thesis prototype for autonomous cyber defense in a controlled cyber range. This first iteration provides a minimal monorepo scaffold with:

- a FastAPI backend for telemetry, detections, ground-truth storage, and metrics
- managed vulnerable-app deployment templates
- Red and Blue agent services
- a React dashboard for a quick demo

The architecture intentionally separates runtime observability from offline evaluation ground truth:

- Blue agent runtime inputs: indirect telemetry only
- Offline evaluator / operator view: attack ground truth, detections, and metrics

## Monorepo Structure

```text
.
├── agents/
│   └── blue_agent/
├── apps/
│   ├── backend/
│   └── frontend/
├── data/
│   └── evaluation_ground_truth/
├── infra/
│   └── docker/
├── logs/
│   └── observability/
└── shared/
    └── python/
```

## Architecture Notes

### Runtime separation

- `POST /api/telemetry/events`: ingest indirect observability events
- `GET /api/blue/telemetry`: Blue-facing telemetry feed only
- `POST /api/blue/detections`: Blue detection output
- `POST /api/evaluation/attacks`: Red/evaluator attack ground truth
- `GET /api/evaluation/attacks`: offline evaluation endpoint, not for Blue runtime use

Blue must never consume attack ground truth during runtime. In this scaffold, that rule is enforced by interface separation and documented agent responsibilities. A later iteration can harden this with process-level isolation and access control.

### Current implementation scope

- In-memory storage for fast iteration
- Demo data seeding on backend startup
- Very simple heuristic Blue placeholder
- Red agent planning that uses managed-target page analysis plus optional local vision reasoning
- Metrics are approximate first-pass metrics for demo and contract validation

## Quick Start

### Option 1: Docker Compose

```bash
docker compose up --build
```

Services:

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:5173`

### Option 2: Run Locally

Backend:

```bash
cd apps/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=../../shared/python uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd apps/frontend
npm install
npm run dev
```

Playwright smoke tests:

```bash
cd apps/frontend
npm install
npx playwright install chromium
npm run test:e2e:list-targets
npm run test:e2e
```

If multiple vulnerable apps are running, pick one explicitly:

```bash
CYBERBOX_TARGET_APP_ID=<running-app-id> npm run test:e2e
```

Blue agent placeholder:

```bash
PYTHONPATH=shared/python python -m agents.blue_agent.main
```

## Browser Smoke Testing

Playwright-based smoke tests live under `apps/frontend/tests/e2e`. They are scoped to
platform-managed local targets only:

- the test helper resolves target URLs from `GET /apps`
- only running apps from the backend-managed registry are allowed
- non-local hosts such as public URLs are rejected
- if more than one app is running, set `CYBERBOX_TARGET_APP_ID`

### Install Playwright

```bash
cd apps/frontend
npm install
npx playwright install chromium
```

### List running managed targets

```bash
cd apps/frontend
npm run test:e2e:list-targets
```

### Run the smoke test suite

```bash
cd apps/frontend
npm run test:e2e
```

### Run headed for visual debugging

```bash
cd apps/frontend
npm run test:e2e:headed
```

### Screenshot output

The homepage smoke test writes a screenshot to:

- `apps/frontend/test-results/screenshots/<template>-<app_id>-homepage.png`

That screenshot is captured after the managed target homepage loads successfully.

### Notes

- If no managed target is running, the test fails with a clear message.
- If multiple managed targets are running, the test requires `CYBERBOX_TARGET_APP_ID`.
- TODO: a future iteration can expose a lightweight backend-triggered smoke-test endpoint or Playwright MCP-backed browser operator adapter.

## Vision-Assisted Red Planning

The Red agent now uses generic vulnerability scenarios rather than app-specific
flows. A bounded page-analysis layer inspects the currently selected
platform-managed local target and recommends applicable scenarios such as:

- `brute_force_login`
- `sql_injection_probe`
- `reflected_xss_probe`
- `file_upload_probe`
- `open_redirect_probe`

The analyzer combines:

- Playwright DOM and accessibility-style extraction
- a screenshot artifact saved under `apps/frontend/test-results/red-agent`
- optional Ollama-backed vision reasoning for page-type understanding

Red-only analysis metadata stays in the Red/operator session-review layers and
is not exposed to the Blue runtime stream.

### Runtime settings

Backend runtime settings live in `apps/backend/config/runtime_settings.json`.
The Red planner and page analyzer currently support:

- `RED_AGENT_REASONER`: `auto`, `ollama`, or `heuristic`
- `RED_AGENT_VISION_REASONER`: `auto`, `heuristic`, or `disabled`
- `RED_AGENT_VISION_MODEL`: defaults to `gemma3:4b`
- `OLLAMA_BASE_URL`
- `OLLAMA_TIMEOUT_SECONDS`
- `OLLAMA_THINK`

If Ollama or the vision-capable model is unavailable, the page analyzer falls
back to DOM heuristics only.

### Planner artifacts

When the Red agent starts a run, it performs a bounded analysis of the selected
managed target homepage and stores:

- analyzed page URL
- screenshot path and artifact URL
- page type classification
- recommended scenarios with confidence scores
- planner rationale and supporting signals

These artifacts are persisted in `data/red_agent_sessions.json` and shown in the
session review UI.

### Local testing

Start the backend and deploy at least one vulnerable app through the platform.
Then create and start an experiment run from the UI. The Red-agent session view
will show:

- page analysis results
- planner-selected generic scenarios
- screenshot evidence for the analyzed page and later scenario steps

For a lower-level manual check of the analyzer runner:

```bash
cd apps/frontend
npx playwright install chromium
CYBERBOX_TARGET_URL=http://localhost:<deployed-target-port> \
CYBERBOX_TARGET_TEMPLATE=dvwa \
CYBERBOX_RUN_ID=manual \
node tests/e2e/helpers/analyzeManagedPage.mjs
```

This manual path is still limited to localhost URLs and is intended only for
repo-local debugging of the analyzer helper.

## Demo Flow

1. Start backend and frontend.
2. Deploy a vulnerable app from the dashboard.
3. Open the dashboard at `http://localhost:5173`.
4. The backend seeds demo observability, ground truth, and a sample detection on startup.
5. Start an experiment run from the dashboard to launch Red and Blue agent workflows.

## Component Interfaces

### Observability event contract

Used for data that Blue is allowed to consume:

- application logs
- HTTP status anomalies
- request path patterns
- service health degradation
- container/runtime signals

Schema: `ObservableEvent`

### Attack execution result contract

Used for offline evaluation only:

- attack type
- target
- execution status
- notes and metadata

Schema: `AttackExecutionRecord`

### Detection output contract

Used by Blue to emit findings:

- predicted attack class
- confidence
- evidence event IDs
- human-readable summary

Schema: `DetectionRecord`

### Metrics contract

Used by the dashboard/evaluator:

- MTTD
- detection accuracy
- classification accuracy
- false positive rate

Schema: `MetricSnapshot`

## Thesis-Oriented TODOs

- Replace in-memory storage with durable persistence.
- Add a real telemetry collector that tails target/app/container logs.
- Integrate Ollama-backed reasoning in the Blue agent without exposing ground truth.
- Replace placeholder attacks with controlled local attack playbooks against the Dockerized target only.
- Add a proper evaluation runner that scores detections after each scenario.
- Add LangGraph orchestration once the simpler control flow is stable.

## Assumptions In This First Iteration

- The dashboard is an operator/research view and may display ground truth for evaluation purposes.
- The Blue agent uses only `/api/blue/*` and never calls `/api/evaluation/*`.
- Attack and detection matching is currently based on classification labels and timestamps, which is acceptable for a demo but not final thesis-grade scoring.
- The vulnerable app is intentionally lightweight and only simulates an unsafe target surface for local testing.
