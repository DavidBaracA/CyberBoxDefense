import { useEffect, useState } from "react";

import DetectionList from "../components/DetectionList";
import DeployAppModal from "../components/DeployAppModal";
import MetricsPanel from "../components/MetricsPanel";
import StatusBar from "../components/StatusBar";
import SummaryCard from "../components/SummaryCard";
import TelemetryList from "../components/TelemetryList";
import VulnerableAppsPanel from "../components/VulnerableAppsPanel";
import {
  deployVulnerableApp,
  getDashboardSnapshot,
  removeVulnerableApp,
  restartVulnerableApp,
  stopVulnerableApp,
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

  async function refresh() {
    const snapshot = await getDashboardSnapshot();
    setState({
      ...snapshot,
      telemetry: safeArray(snapshot.telemetry),
      detections: safeArray(snapshot.detections),
      vulnerableApps: safeArray(snapshot.vulnerableApps),
      vulnerableAppTemplates: safeArray(snapshot.vulnerableAppTemplates),
      metrics: snapshot.metrics || {},
      lastUpdated: new Date().toISOString(),
    });
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

  const latestAttackType = getLatestAttackType(state.detections);
  const telemetryCount =
    state.metrics?.telemetry_event_count ?? state.telemetry.length ?? 0;
  const detectionCount =
    state.metrics?.detection_count ?? state.detections.length ?? 0;

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
