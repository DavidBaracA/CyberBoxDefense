const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const endpointGroups = {
  health: ["/health", "/api/health"],
  telemetry: ["/telemetry", "/api/telemetry", "/api/telemetry/events"],
  detections: ["/detections", "/api/detections"],
  metrics: ["/metrics", "/api/metrics"],
  vulnerableApps: ["/apps"],
  vulnerableAppTemplates: ["/apps/templates"],
  blueAgentStatus: ["/blue-agent/status"],
  blueAgentLogs: ["/blue-agent/logs"],
  blueAgentModels: ["/blue-agent/models"],
  redAgentStatus: ["/red-agent/status"],
  redAgentScenarios: ["/red-agent/scenarios"],
  redAgentLogs: ["/red-agent/logs"],
  redAgentSessions: ["/red-agent/sessions"],
  configRunForm: ["/api/config/run-form"],
};

function buildWebSocketUrl(path) {
  const url = new URL(API_BASE_URL);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = path;
  url.search = "";
  url.hash = "";
  return url.toString();
}

async function fetchJson(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, options);
  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;
    try {
      const body = await response.json();
      if (body?.detail) {
        detail = body.detail;
      }
    } catch {
      // Keep the fallback error message when the body is not JSON.
    }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  if (response.status === 204) {
    return null;
  }
  return response.json();
}

async function tryEndpoints(paths, fallbackValue) {
  for (const path of paths) {
    try {
      const payload = await fetchJson(path);
      return { payload, path };
    } catch (error) {
      if (error.status === 404) {
        continue;
      }
      throw error;
    }
  }
  return { payload: fallbackValue, path: null };
}

function asArray(payload, candidateKeys = []) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (payload && typeof payload === "object") {
    for (const key of candidateKeys) {
      if (Array.isArray(payload[key])) {
        return payload[key];
      }
    }
  }

  return [];
}

function asObject(payload) {
  return payload && typeof payload === "object" ? payload : {};
}

export async function getBackendHealth() {
  try {
    const { payload, path } = await tryEndpoints(endpointGroups.health, null);
    const status = asObject(payload).status;
    return {
      ok: Boolean(path && status === "ok"),
      label: path && status === "ok" ? "Connected" : "Unavailable",
      path,
    };
  } catch (error) {
    return {
      ok: false,
      label: "Unavailable",
      path: null,
      error: error.message,
    };
  }
}

export async function getTelemetry() {
  const { payload } = await tryEndpoints(endpointGroups.telemetry, []);
  return asArray(payload, ["events", "items", "telemetry"]);
}

export async function getDetections() {
  const { payload } = await tryEndpoints(endpointGroups.detections, []);
  return asArray(payload, ["detections", "items"]);
}

export async function getMetrics() {
  const { payload } = await tryEndpoints(endpointGroups.metrics, {});
  return asObject(payload);
}

export async function getVulnerableApps() {
  const { payload } = await tryEndpoints(endpointGroups.vulnerableApps, []);
  return asArray(payload, ["apps", "items"]);
}

export async function getVulnerableAppTemplates() {
  const { payload } = await tryEndpoints(endpointGroups.vulnerableAppTemplates, []);
  return asArray(payload, ["templates", "items"]);
}

export async function deployVulnerableApp(request) {
  return fetchJson("/apps/deploy", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
}

export async function stopVulnerableApp(appId) {
  return fetchJson(`/apps/${appId}/stop`, {
    method: "POST",
  });
}

export async function restartVulnerableApp(appId) {
  return fetchJson(`/apps/${appId}/restart`, {
    method: "POST",
  });
}

export async function removeVulnerableApp(appId) {
  return fetchJson(`/apps/${appId}`, {
    method: "DELETE",
  });
}

export async function getBlueAgentStatus() {
  const { payload } = await tryEndpoints(endpointGroups.blueAgentStatus, {});
  return asObject(payload);
}

export async function getBlueAgentLogs() {
  const { payload } = await tryEndpoints(endpointGroups.blueAgentLogs, {});
  return asArray(payload, ["logs", "items"]);
}

export async function getBlueAgentModels() {
  const { payload } = await tryEndpoints(endpointGroups.blueAgentModels, []);
  return asArray(payload, ["models", "items"]);
}

export async function startBlueAgent(request = {}) {
  return fetchJson("/blue-agent/start", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
}

export async function stopBlueAgent() {
  return fetchJson("/blue-agent/stop", {
    method: "POST",
  });
}

export function getBlueAgentWebSocketUrl() {
  return buildWebSocketUrl("/ws/blue-agent");
}

export async function getRedAgentStatus() {
  const { payload } = await tryEndpoints(endpointGroups.redAgentStatus, {});
  return asObject(payload);
}

export async function getRedAgentScenarios() {
  const { payload } = await tryEndpoints(endpointGroups.redAgentScenarios, []);
  return asArray(payload, ["scenarios", "items"]);
}

export async function getRedAgentSessions() {
  const { payload } = await tryEndpoints(endpointGroups.redAgentSessions, []);
  return asArray(payload, ["sessions", "items"]);
}

export async function getRedAgentSessionDetail(sessionId) {
  return fetchJson(`/red-agent/sessions/${sessionId}`);
}

export async function startRedAgent(request) {
  return fetchJson("/red-agent/start", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
}

export async function getRunFormConfig() {
  const { payload } = await tryEndpoints(endpointGroups.configRunForm, {});
  return asObject(payload);
}

export async function createRun(request) {
  return fetchJson("/api/runs", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
}

export async function startRun(runId) {
  return fetchJson(`/api/runs/${runId}/start`, {
    method: "POST",
  });
}

export async function stopRedAgent() {
  return fetchJson("/red-agent/stop", {
    method: "POST",
  });
}

export function getRedAgentWebSocketUrl() {
  return buildWebSocketUrl("/ws/red-agent");
}

export async function getDashboardSnapshot() {
  const [health, telemetry, detections, metrics, vulnerableApps, vulnerableAppTemplates, blueAgentStatus, redAgentStatus, redAgentScenarios] =
    await Promise.allSettled([
      getBackendHealth(),
      getTelemetry(),
      getDetections(),
      getMetrics(),
      getVulnerableApps(),
      getVulnerableAppTemplates(),
      getBlueAgentStatus(),
      getRedAgentStatus(),
      getRedAgentScenarios(),
    ]);

  return {
    connection:
      health.status === "fulfilled"
        ? health.value
        : { ok: false, label: "Unavailable", path: null, error: health.reason?.message },
    telemetry: telemetry.status === "fulfilled" ? telemetry.value : [],
    detections: detections.status === "fulfilled" ? detections.value : [],
    metrics: metrics.status === "fulfilled" ? metrics.value : {},
    vulnerableApps: vulnerableApps.status === "fulfilled" ? vulnerableApps.value : [],
    vulnerableAppTemplates:
      vulnerableAppTemplates.status === "fulfilled" ? vulnerableAppTemplates.value : [],
    blueAgentStatus: blueAgentStatus.status === "fulfilled" ? blueAgentStatus.value : {},
    redAgentStatus: redAgentStatus.status === "fulfilled" ? redAgentStatus.value : {},
    redAgentScenarios: redAgentScenarios.status === "fulfilled" ? redAgentScenarios.value : [],
    errors: [
      health.status === "rejected" ? health.reason?.message : null,
      telemetry.status === "rejected" ? telemetry.reason?.message : null,
      detections.status === "rejected" ? detections.reason?.message : null,
      metrics.status === "rejected" ? metrics.reason?.message : null,
      vulnerableApps.status === "rejected" ? vulnerableApps.reason?.message : null,
      vulnerableAppTemplates.status === "rejected" ? vulnerableAppTemplates.reason?.message : null,
      blueAgentStatus.status === "rejected" ? blueAgentStatus.reason?.message : null,
      redAgentStatus.status === "rejected" ? redAgentStatus.reason?.message : null,
      redAgentScenarios.status === "rejected" ? redAgentScenarios.reason?.message : null,
    ].filter(Boolean),
  };
}

export { API_BASE_URL };
