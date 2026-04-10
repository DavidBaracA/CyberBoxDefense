import { useEffect, useState } from "react";

import BlueAgentPanel from "../components/BlueAgentPanel";
import DetectionList from "../components/DetectionList";
import DeployAppModal from "../components/DeployAppModal";
import MetricsPanel from "../components/MetricsPanel";
import RedAgentPanel from "../components/RedAgentPanel";
import StatusBar from "../components/StatusBar";
import SummaryCard from "../components/SummaryCard";
import TelemetryList from "../components/TelemetryList";
import VulnerableAppsPanel from "../components/VulnerableAppsPanel";
import {
  deployVulnerableApp,
  getBlueAgentWebSocketUrl,
  getDashboardSnapshot,
  getRedAgentWebSocketUrl,
  removeVulnerableApp,
  restartVulnerableApp,
  startRedAgent,
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

export default function Dashboard() {
  const [state, setState] = useState(initialState);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [appsLoading, setAppsLoading] = useState(true);
  const [appsError, setAppsError] = useState("");
  const [isSubmittingDeploy, setIsSubmittingDeploy] = useState(false);
  const [isActingOnApp, setIsActingOnApp] = useState(false);
  const [blueAgentError, setBlueAgentError] = useState("");
  const [isStartingBlueAgent, setIsStartingBlueAgent] = useState(false);
  const [isStoppingBlueAgent, setIsStoppingBlueAgent] = useState(false);
  const [blueAgentStreamState, setBlueAgentStreamState] = useState("connecting");
  const [redAgentError, setRedAgentError] = useState("");
  const [isStartingRedAgent, setIsStartingRedAgent] = useState(false);
  const [isStoppingRedAgent, setIsStoppingRedAgent] = useState(false);
  const [redAgentStreamState, setRedAgentStreamState] = useState("connecting");

  async function refresh() {
    const snapshot = await getDashboardSnapshot();
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
      } catch (error) {
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
          setState((current) => ({
            ...current,
            redAgentLogs: [],
          }));
          return;
        }

        if (payload?.type === "history") {
          setState((current) => ({
            ...current,
            redAgentLogs: safeArray(payload.logs),
          }));
          return;
        }

        if (payload?.type === "log" && payload.entry) {
          setState((current) => ({
            ...current,
            redAgentLogs: [...safeArray(current.redAgentLogs), payload.entry].slice(-400),
          }));
          return;
        }

        if (payload?.type === "status" && payload.state) {
          setState((current) => ({
            ...current,
            redAgentStatus: payload.state,
          }));
        }
      };

      socket.onerror = () => {
        if (!isClosed) {
          setRedAgentStreamState("disconnected");
        }
      };

      socket.onclose = () => {
        if (isClosed) {
          return;
        }
        setRedAgentStreamState("disconnected");
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
          setState((current) => ({
            ...current,
            blueAgentLogs: [],
          }));
          return;
        }

        if (payload?.type === "history") {
          setState((current) => ({
            ...current,
            blueAgentLogs: safeArray(payload.logs),
          }));
          return;
        }

        if (payload?.type === "log" && payload.entry) {
          setState((current) => ({
            ...current,
            blueAgentLogs: [...safeArray(current.blueAgentLogs), payload.entry].slice(-400),
          }));
          return;
        }

        if (payload?.type === "status" && payload.state) {
          setState((current) => ({
            ...current,
            blueAgentStatus: payload.state,
          }));
        }
      };

      socket.onerror = () => {
        if (!isClosed) {
          setBlueAgentStreamState("disconnected");
        }
      };

      socket.onclose = () => {
        if (isClosed) {
          return;
        }
        setBlueAgentStreamState("disconnected");
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
      await deployVulnerableApp(payload);
      setIsDeployModalOpen(false);
      await refresh();
    } catch (error) {
      setAppsError(error.message);
    } finally {
      setIsSubmittingDeploy(false);
    }
  }

  async function handleAction(action) {
    setIsActingOnApp(true);
    setAppsError("");
    try {
      await action();
      await refresh();
    } catch (error) {
      setAppsError(error.message);
    } finally {
      setIsActingOnApp(false);
    }
  }

  async function handleStartBlueAgent() {
    setIsStartingBlueAgent(true);
    setBlueAgentError("");
    try {
      await startBlueAgent();
      await refresh();
    } catch (error) {
      setBlueAgentError(error.message);
    } finally {
      setIsStartingBlueAgent(false);
    }
  }

  async function handleStopBlueAgent() {
    setIsStoppingBlueAgent(true);
    setBlueAgentError("");
    try {
      await stopBlueAgent();
      await refresh();
    } catch (error) {
      setBlueAgentError(error.message);
    } finally {
      setIsStoppingBlueAgent(false);
    }
  }

  async function handleStartRedAgent(payload) {
    setIsStartingRedAgent(true);
    setRedAgentError("");
    try {
      await startRedAgent(payload);
      await refresh();
    } catch (error) {
      setRedAgentError(error.message);
    } finally {
      setIsStartingRedAgent(false);
    }
  }

  async function handleStopRedAgent() {
    setIsStoppingRedAgent(true);
    setRedAgentError("");
    try {
      await stopRedAgent();
      await refresh();
    } catch (error) {
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
          scenarios={state.redAgentScenarios}
          isStarting={isStartingRedAgent}
          isStopping={isStoppingRedAgent}
          error={redAgentError}
          onStart={handleStartRedAgent}
          onStop={handleStopRedAgent}
        />

        <BlueAgentPanel
          state={state.blueAgentStatus}
          logs={state.blueAgentLogs}
          streamState={blueAgentStreamState}
          hasRunningTarget={hasRunningTarget}
          isStarting={isStartingBlueAgent}
          isStopping={isStoppingBlueAgent}
          error={blueAgentError}
          onStart={handleStartBlueAgent}
          onStop={handleStopBlueAgent}
        />
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
    </main>
  );
}
