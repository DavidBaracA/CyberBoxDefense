# CyberBoxDefense

CyberBoxDefense is a local MSc thesis prototype for autonomous cyber defense in a controlled cyber range. This first iteration provides a minimal monorepo scaffold with:

- a vulnerable target container
- a FastAPI backend for telemetry, detections, ground-truth storage, and metrics
- placeholder Red and Blue agents
- a React dashboard for a quick demo

The architecture intentionally separates runtime observability from offline evaluation ground truth:

- Blue agent runtime inputs: indirect telemetry only
- Offline evaluator / operator view: attack ground truth, detections, and metrics

## Monorepo Structure

```text
.
├── agents/
│   ├── blue_agent/
│   └── red_agent/
├── apps/
│   ├── backend/
│   └── frontend/
├── data/
│   └── evaluation_ground_truth/
├── infra/
│   └── docker/
├── logs/
│   └── observability/
├── shared/
│   └── python/
└── targets/
    └── vulnerable_app/
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
- Very simple Red placeholder that triggers the target and records synthetic results
- Metrics are approximate first-pass metrics for demo and contract validation

## Quick Start

### Option 1: Docker Compose

```bash
docker compose up --build
```

Services:

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:5173`
- Vulnerable app: `http://localhost:8081`

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

Vulnerable app:

```bash
cd targets/vulnerable_app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Red agent placeholder:

```bash
PYTHONPATH=shared/python python -m agents.red_agent.main
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

## Demo Flow

1. Start backend, frontend, and vulnerable app.
2. Open the dashboard at `http://localhost:5173`.
3. The backend seeds demo observability, ground truth, and a sample detection on startup.
4. Optionally run the Red agent placeholder to trigger the target and submit additional records.
5. Optionally run the Blue agent placeholder to read indirect telemetry and publish heuristic detections.

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
