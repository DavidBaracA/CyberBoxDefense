import { useEffect, useState } from "react";

import BlueAgentPanel from "../components/BlueAgentPanel";
import DetectionList from "../components/DetectionList";
import DeployAppModal from "../components/DeployAppModal";
import ExperimentRunModal from "../components/ExperimentRunModal";
import MetricsPanel from "../components/MetricsPanel";
import RedAgentPanel from "../components/RedAgentPanel";
import RedAgentSessionsModal from "../components/RedAgentSessionsModal";
import StatusBar from "../components/StatusBar";
import SummaryCard from "../components/SummaryCard";
import TelemetryList from "../components/TelemetryList";
import VulnerableAppsPanel from "../components/VulnerableAppsPanel";
import {
  createRun,
  deployVulnerableApp,
  getBlueAgentModels,
  getBlueAgentWebSocketUrl,
  getDashboardSnapshot,
  getRedAgentWebSocketUrl,
  getRunFormConfig,
  removeVulnerableApp,
  restartVulnerableApp,
  startRun,
  startBlueAgent,
  stopVulnerableApp,
  stopRedAgent,
  stopBlueAgent,
} from "../services/api";

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeMetric(value) {
  if (value === null || value === undefined) {
    return "N/A";
  }

  if (typeof value === "number") {
    return value.toFixed(2);
  }

  return String(value);
}

function getLatestAttackType(detections) {
  const latest = safeArray(detections).at(-1);
  return latest?.classification || latest?.predicted_attack_type || "No detections yet";
}

const initialState = {
  connection: { ok: false, label: "Checking connection", path: null },
  telemetry: [],
  detections: [],
  metrics: {},
  vulnerableApps: [],
  vulnerableAppTemplates: [],
  blueAgentStatus: {},
  blueAgentLogs: [],
  redAgentStatus: {},
  redAgentLogs: [],
  redAgentScenarios: [],
  errors: [],
  lastUpdated: null,
};

function formatDebugPayload(payload) {
  try {
    return JSON.stringify(payload, null, 2);
  } catch {
    return String(payload);
  }
}

function extractOllamaDebugEntry(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  if (typeof payload.type === "string" && payload.raw_response) {
    return {
      level: payload.level || "info",
      type: payload.type,
      raw_response: String(payload.raw_response),
      timestamp: payload.timestamp,
    };
  }

  const message = typeof payload.message === "string" ? payload.message : "";
  const rawPrefix = "Planning raw model response:";
  const visionRawPrefix = "Vision raw model response:";
  const errorPrefix = "Planning model error:";
  const fallbackPrefix = "Planning model fallback:";

  if (message.startsWith(visionRawPrefix)) {
    return {
      level: payload.level || "info",
      type: "vision_raw_response",
      raw_response: message.slice(visionRawPrefix.length).trim(),
      timestamp: payload.timestamp,
    };
  }

  if (message.startsWith(rawPrefix)) {
    return {
      level: payload.level || "info",
      type: "raw_response",
      raw_response: message.slice(rawPrefix.length).trim(),
      timestamp: payload.timestamp,
    };
  }

  if (message.startsWith(errorPrefix)) {
    return {
      level: payload.level || "warning",
      type: "error",
      error: message.slice(errorPrefix.length).trim(),
      timestamp: payload.timestamp,
    };
  }

  if (message.startsWith(fallbackPrefix)) {
    return {
      level: payload.level || "warning",
      type: "fallback",
      fallback: message.slice(fallbackPrefix.length).trim(),
      timestamp: payload.timestamp,
    };
  }

  return null;
}

export default function Dashboard() {
  const [state, setState] = useState(initialState);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [isExperimentModalOpen, setIsExperimentModalOpen] = useState(false);
  const [isRedSessionsModalOpen, setIsRedSessionsModalOpen] = useState(false);
  const [appsLoading, setAppsLoading] = useState(true);
  const [appsError, setAppsError] = useState("");
  const [isSubmittingDeploy, setIsSubmittingDeploy] = useState(false);
  const [isActingOnApp, setIsActingOnApp] = useState(false);
  const [blueAgentError, setBlueAgentError] = useState("");
  const [blueModelOptions, setBlueModelOptions] = useState([]);
  const [selectedBlueModelId, setSelectedBlueModelId] = useState("gemma3:4b");
  const [isStartingBlueAgent, setIsStartingBlueAgent] = useState(false);
  const [isStoppingBlueAgent, setIsStoppingBlueAgent] = useState(false);
  const [blueAgentStreamState, setBlueAgentStreamState] = useState("connecting");
  const [redAgentError, setRedAgentError] = useState("");
  const [isStartingRedAgent, setIsStartingRedAgent] = useState(false);
  const [isStoppingRedAgent, setIsStoppingRedAgent] = useState(false);
  const [redAgentStreamState, setRedAgentStreamState] = useState("connecting");
  const [runFormConfig, setRunFormConfig] = useState(null);
  const [agentDebugEntries, setAgentDebugEntries] = useState([]);

  function appendAgentDebug(source, label, payload) {
    const filteredPayload = extractOllamaDebugEntry(payload);
    if (!filteredPayload) {
      return;
    }

    const entry = {
      entryId: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      timestamp: new Date().toISOString(),
      source,
      label,
      payload: formatDebugPayload(filteredPayload),
    };
    setAgentDebugEntries((current) => [entry, ...current].slice(0, 120));
  }

  async function refresh() {
    const snapshot = await getDashboardSnapshot();
    appendAgentDebug("api", "getDashboardSnapshot", {
      redAgentStatus: snapshot.redAgentStatus || {},
      blueAgentStatus: snapshot.blueAgentStatus || {},
      runningManagedApps: safeArray(snapshot.vulnerableApps).filter((app) => app?.status === "running"),
      errors: snapshot.errors || [],
    });
    setState((current) => ({
      ...snapshot,
      telemetry: safeArray(snapshot.telemetry),
      detections: safeArray(snapshot.detections),
      vulnerableApps: safeArray(snapshot.vulnerableApps),
      vulnerableAppTemplates: safeArray(snapshot.vulnerableAppTemplates),
      blueAgentStatus: snapshot.blueAgentStatus || current.blueAgentStatus || {},
      blueAgentLogs: current.blueAgentLogs,
      redAgentStatus: snapshot.redAgentStatus || current.redAgentStatus || {},
      redAgentLogs: current.redAgentLogs,
      redAgentScenarios: safeArray(snapshot.redAgentScenarios),
      metrics: snapshot.metrics || {},
      lastUpdated: new Date().toISOString(),
    }));
    setAppsLoading(false);
    setAppsError("");
  }

  useEffect(() => {
    let isMounted = true;

    async function refreshSafely() {
      try {
        await refresh();
        const config = await getRunFormConfig();
        const blueModels = await getBlueAgentModels();
        appendAgentDebug("api", "getRunFormConfig", config);
        appendAgentDebug("api", "getBlueAgentModels", blueModels);
        if (isMounted) {
          setRunFormConfig(config);
          setBlueModelOptions(blueModels);
          if (Array.isArray(blueModels) && blueModels.length > 0) {
            setSelectedBlueModelId((current) =>
              current || blueModels[0].model_id
            );
          }
        }
      } catch (error) {
        appendAgentDebug("api-error", "initial refresh", { message: error.message });
        if (!isMounted) {
          return;
        }
        setAppsLoading(false);
        setAppsError(error.message);
      }
    }

    refreshSafely();
    const timerId = window.setInterval(refreshSafely, 3000);

    return () => {
      isMounted = false;
      window.clearInterval(timerId);
    };
  }, []);

  useEffect(() => {
    let socket;
    let retryId;
    let isClosed = false;

    function connect() {
      if (isClosed) {
        return;
      }

      setRedAgentStreamState("connecting");
      socket = new WebSocket(getRedAgentWebSocketUrl());

      socket.onopen = () => {
        if (!isClosed) {
          setRedAgentStreamState("connected");
          appendAgentDebug("ws-red", "socket open", { streamState: "connected" });
        }
      };

      socket.onmessage = (event) => {
        let payload;
        try {
          payload = JSON.parse(event.data);
        } catch {
          return;
        }

        if (payload?.type === "reset") {
          appendAgentDebug("ws-red", "reset", payload);
          setState((current) => ({
            ...current,
            redAgentLogs: [],
          }));
          return;
        }

        if (payload?.type === "history") {
          appendAgentDebug("ws-red", "history", { logCount: safeArray(payload.logs).length });
          setState((current) => ({
            ...current,
            redAgentLogs: safeArray(payload.logs),
          }));
          return;
        }

        if (payload?.type === "log" && payload.entry) {
          appendAgentDebug("ws-red", "log", payload.entry);
          setState((current) => ({
            ...current,
            redAgentLogs: [...safeArray(current.redAgentLogs), payload.entry].slice(-400),
          }));
          return;
        }

        if (payload?.type === "debug" && payload.entry) {
          appendAgentDebug("ws-red", "debug", payload.entry);
          return;
        }

        if (payload?.type === "status" && payload.state) {
          appendAgentDebug("ws-red", "status", payload.state);
          setState((current) => ({
            ...current,
            redAgentStatus: payload.state,
          }));
        }
      };

      socket.onerror = () => {
        if (!isClosed) {
          setRedAgentStreamState("disconnected");
          appendAgentDebug("ws-red", "socket error", { streamState: "disconnected" });
        }
      };

      socket.onclose = () => {
        if (isClosed) {
          return;
        }
        setRedAgentStreamState("disconnected");
        appendAgentDebug("ws-red", "socket close", { streamState: "disconnected" });
        retryId = window.setTimeout(connect, 3000);
      };
    }

    connect();

    return () => {
      isClosed = true;
      setRedAgentStreamState("closed");
      if (retryId) {
        window.clearTimeout(retryId);
      }
      if (socket) {
        socket.close();
      }
    };
  }, []);

  useEffect(() => {
    let socket;
    let retryId;
    let isClosed = false;

    function connect() {
      if (isClosed) {
        return;
      }

      setBlueAgentStreamState("connecting");
      socket = new WebSocket(getBlueAgentWebSocketUrl());

      socket.onopen = () => {
        if (!isClosed) {
          setBlueAgentStreamState("connected");
          appendAgentDebug("ws-blue", "socket open", { streamState: "connected" });
        }
      };

      socket.onmessage = (event) => {
        let payload;
        try {
          payload = JSON.parse(event.data);
        } catch {
          return;
        }

        if (payload?.type === "reset") {
          appendAgentDebug("ws-blue", "reset", payload);
          setState((current) => ({
            ...current,
            blueAgentLogs: [],
          }));
          return;
        }

        if (payload?.type === "history") {
          appendAgentDebug("ws-blue", "history", { logCount: safeArray(payload.logs).length });
          setState((current) => ({
            ...current,
            blueAgentLogs: safeArray(payload.logs),
          }));
          return;
        }

        if (payload?.type === "log" && payload.entry) {
          appendAgentDebug("ws-blue", "log", payload.entry);
          setState((current) => ({
            ...current,
            blueAgentLogs: [...safeArray(current.blueAgentLogs), payload.entry].slice(-400),
          }));
          return;
        }

        if (payload?.type === "status" && payload.state) {
          appendAgentDebug("ws-blue", "status", payload.state);
          setState((current) => ({
            ...current,
            blueAgentStatus: payload.state,
          }));
        }
      };

      socket.onerror = () => {
        if (!isClosed) {
          setBlueAgentStreamState("disconnected");
          appendAgentDebug("ws-blue", "socket error", { streamState: "disconnected" });
        }
      };

      socket.onclose = () => {
        if (isClosed) {
          return;
        }
        setBlueAgentStreamState("disconnected");
        appendAgentDebug("ws-blue", "socket close", { streamState: "disconnected" });
        retryId = window.setTimeout(connect, 3000);
      };
    }

    connect();

    return () => {
      isClosed = true;
      setBlueAgentStreamState("closed");
      if (retryId) {
        window.clearTimeout(retryId);
      }
      if (socket) {
        socket.close();
      }
    };
  }, []);

  async function handleDeploy(payload) {
    setIsSubmittingDeploy(true);
    setAppsError("");
    try {
      const response = await deployVulnerableApp(payload);
      appendAgentDebug("api", "deployVulnerableApp", response);
      setIsDeployModalOpen(false);
      await refresh();
    } catch (error) {
      appendAgentDebug("api-error", "deployVulnerableApp", { message: error.message, payload });
      setAppsError(error.message);
    } finally {
      setIsSubmittingDeploy(false);
    }
  }

  async function handleAction(action) {
    setIsActingOnApp(true);
    setAppsError("");
    try {
      const response = await action();
      appendAgentDebug("api", "vulnerableAppAction", response);
      await refresh();
    } catch (error) {
      appendAgentDebug("api-error", "vulnerableAppAction", { message: error.message });
      setAppsError(error.message);
    } finally {
      setIsActingOnApp(false);
    }
  }

  async function handleStartBlueAgent() {
    setIsStartingBlueAgent(true);
    setBlueAgentError("");
    try {
      const response = await startBlueAgent({
        model_id: selectedBlueModelId || undefined,
      });
      appendAgentDebug("api", "startBlueAgent", response);
      await refresh();
    } catch (error) {
      appendAgentDebug("api-error", "startBlueAgent", { message: error.message });
      setBlueAgentError(error.message);
    } finally {
      setIsStartingBlueAgent(false);
    }
  }

  async function handleStopBlueAgent() {
    setIsStoppingBlueAgent(true);
    setBlueAgentError("");
    try {
      const response = await stopBlueAgent();
      appendAgentDebug("api", "stopBlueAgent", response);
      await refresh();
    } catch (error) {
      appendAgentDebug("api-error", "stopBlueAgent", { message: error.message });
      setBlueAgentError(error.message);
    } finally {
      setIsStoppingBlueAgent(false);
    }
  }

  async function handleStartRedAgent(payload) {
    setIsStartingRedAgent(true);
    setRedAgentError("");
    try {
      const run = await createRun({
        app_id: payload.target_app_id,
        config: payload.config,
      });
      appendAgentDebug("api", "createRun", run);
      const startResponse = await startRun(run.run_id);
      appendAgentDebug("api", "startRun", startResponse);
      setIsExperimentModalOpen(false);
      await refresh();
    } catch (error) {
      appendAgentDebug("api-error", "startRun flow", {
        message: error.message,
        target_app_id: payload.target_app_id,
      });
      setRedAgentError(error.message);
    } finally {
      setIsStartingRedAgent(false);
    }
  }

  async function handleStopRedAgent() {
    setIsStoppingRedAgent(true);
    setRedAgentError("");
    try {
      const response = await stopRedAgent();
      appendAgentDebug("api", "stopRedAgent", response);
      await refresh();
    } catch (error) {
      appendAgentDebug("api-error", "stopRedAgent", { message: error.message });
      setRedAgentError(error.message);
    } finally {
      setIsStoppingRedAgent(false);
    }
  }

  const latestAttackType = getLatestAttackType(state.detections);
  const telemetryCount =
    state.metrics?.telemetry_event_count ?? state.telemetry.length ?? 0;
  const detectionCount =
    state.metrics?.detection_count ?? state.detections.length ?? 0;
  const hasRunningTarget = state.vulnerableApps.some((app) => app?.status === "running");

  return (
    <main className="app-shell">
      <StatusBar
        title="CyberBoxDefense"
        subtitle="Autonomous cyber defense dashboard for telemetry, Blue detections, and evaluation metrics in a controlled local environment."
        connection={state.connection}
        lastUpdated={state.lastUpdated}
      />

      {state.errors.length > 0 ? (
        <section className="error-strip panel">
          <p className="error-banner">
            Partial backend data issue: {state.errors[0]}
          </p>
        </section>
      ) : null}

      <section className="summary-grid">
        <SummaryCard
          label="Total Telemetry Events"
          value={telemetryCount}
          detail="Indirect observability from the app or monitoring layer."
        />
        <SummaryCard
          label="Total Detections"
          value={detectionCount}
          detail="Blue-side outputs available for the current run."
        />
        <SummaryCard
          label="Latest Predicted Attack"
          value={latestAttackType}
          detail="Uses the newest available detection classification."
        />
        <SummaryCard
          label="Current MTTD"
          value={safeMetric(state.metrics?.mean_time_to_detection_seconds)}
          detail="Displayed in seconds when the backend provides the metric."
        />
      </section>

      <section className="content-grid">
        <TelemetryList items={state.telemetry} />
        <DetectionList items={state.detections} />
      </section>

      <section className="agent-grid">
        <RedAgentPanel
          state={state.redAgentStatus}
          logs={state.redAgentLogs}
          streamState={redAgentStreamState}
          runningApps={state.vulnerableApps.filter((app) => app?.status === "running")}
          allApps={state.vulnerableApps}
          isStopping={isStoppingRedAgent}
          error={redAgentError}
          onOpenStart={() => setIsExperimentModalOpen(true)}
          onOpenSessions={() => setIsRedSessionsModalOpen(true)}
          onStop={handleStopRedAgent}
        />

        <BlueAgentPanel
          state={state.blueAgentStatus}
          logs={state.blueAgentLogs}
          streamState={blueAgentStreamState}
          hasRunningTarget={hasRunningTarget}
          modelOptions={blueModelOptions}
          selectedModelId={selectedBlueModelId}
          onSelectModel={setSelectedBlueModelId}
          isStarting={isStartingBlueAgent}
          isStopping={isStoppingBlueAgent}
          error={blueAgentError}
          onStart={handleStartBlueAgent}
          onStop={handleStopBlueAgent}
        />
      </section>

      <section className="panel agent-debug-panel">
        <div className="panel-header panel-header-row">
          <div>
            <h2>Agent Debug</h2>
            <p className="panel-copy">
              Raw Ollama planner responses and planning errors captured from the Red-agent stream.
            </p>
          </div>
          <button
            className="ghost-button"
            type="button"
            onClick={() => setAgentDebugEntries([])}
          >
            Clear Debug Log
          </button>
        </div>
        <div className="agent-debug-console">
          {agentDebugEntries.length === 0 ? (
            <div className="empty-state">No Ollama planner debug events captured yet.</div>
          ) : (
            agentDebugEntries.map((entry) => (
              <article key={entry.entryId} className="agent-debug-entry">
                <div className="agent-debug-meta">
                  <strong>{entry.label}</strong>
                  <span>{entry.source}</span>
                  <span>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                </div>
                <pre className="agent-debug-payload">{entry.payload}</pre>
              </article>
            ))
          )}
        </div>
      </section>

      <MetricsPanel metrics={state.metrics} />

      <VulnerableAppsPanel
        apps={state.vulnerableApps}
        templates={state.vulnerableAppTemplates}
        isLoading={appsLoading}
        isActing={isActingOnApp}
        error={appsError}
        onOpenDeploy={() => setIsDeployModalOpen(true)}
        onStop={(appId) => handleAction(() => stopVulnerableApp(appId))}
        onRestart={(appId) => handleAction(() => restartVulnerableApp(appId))}
        onRemove={(appId) => handleAction(() => removeVulnerableApp(appId))}
      />

      <DeployAppModal
        isOpen={isDeployModalOpen}
        onClose={() => setIsDeployModalOpen(false)}
        onDeploy={handleDeploy}
        isSubmitting={isSubmittingDeploy}
        error={appsError}
        templates={state.vulnerableAppTemplates}
      />

      <ExperimentRunModal
        isOpen={isExperimentModalOpen}
        onClose={() => setIsExperimentModalOpen(false)}
        onStart={handleStartRedAgent}
        isSubmitting={isStartingRedAgent}
        error={redAgentError}
        runningApps={state.vulnerableApps.filter((app) => app?.status === "running")}
        allApps={state.vulnerableApps}
        scenarios={state.redAgentScenarios}
        runFormConfig={runFormConfig}
      />

      <RedAgentSessionsModal
        isOpen={isRedSessionsModalOpen}
        onClose={() => setIsRedSessionsModalOpen(false)}
      />
    </main>
  );
}
