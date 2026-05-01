import RedAgentTerminal from "./RedAgentTerminal";
import { API_BASE_URL } from "../services/api";

function StatusBadge({ status }) {
  const normalized = status || "idle";
  return (
    <span className={`status-badge red-status-badge is-${normalized}`}>
      <span className="status-dot" />
      {normalized}
    </span>
  );
}

function formatPhase(phase) {
  if (!phase) {
    return "idle";
  }
  return String(phase).replace(/_/g, " ");
}

export default function RedAgentPanel({
  state,
  logs,
  streamState,
  runningApps,
  allApps,
  isStopping,
  error,
  onOpenStart,
  onOpenSessions,
  onStop,
}) {
  const rows = Array.isArray(runningApps) ? runningApps : [];
  const managedRows = Array.isArray(allApps) ? allApps : [];

  const status = state?.status || "idle";
  const isActive = status === "running" || status === "starting";
  const startDisabled = !rows.length || isActive;
  const stopDisabled = isStopping || !isActive;
  const hasManagedApps = managedRows.length > 0;
  const inactiveManagedSummary = managedRows
    .map((app) => `${app.name || app.template_id || "app"}: ${app.status || "unknown"}`)
    .join(", ");
  const evidenceUrl = state?.latest_artifact_url || state?.page_analysis_artifact_url;
  const evidencePath = state?.latest_artifact_path || state?.page_analysis_artifact_path;
  const isPageAnalysisEvidence = evidenceUrl === state?.page_analysis_artifact_url;

  return (
    <section className="panel red-agent-panel">
      <div className="panel-header panel-header-row">
        <div>
          <h2>Red Agent</h2>
          <p className="panel-copy">
            Operator-controlled bounded scenario runner for local vulnerable targets only.
          </p>
        </div>
        <StatusBadge status={status} />
      </div>

      <div className="red-agent-meta">
        <p className="panel-copy">{state?.message || "Red agent is idle."}</p>
        <div className="blue-agent-runtime-details">
          <span>Terminal stream: {streamState || "connecting"}</span>
          <span>Phase: {formatPhase(state?.runtime_phase)}</span>
          <span>Target: {state?.target_name || "No active target"}</span>
          <span>Run ID: {state?.run_id || "No active run"}</span>
          <span>Planner model: {state?.selected_model_label || "Default"}</span>
          <span>Ground-truth events: {state?.emitted_events_count ?? 0}</span>
          <span>
            Latest artifact: {state?.latest_artifact_path ? "available" : "none"}
          </span>
        </div>
        {rows.length === 0 ? (
          <p className="warning-copy">
            {hasManagedApps
              ? `No platform-managed vulnerable app is currently running. Managed app states: ${inactiveManagedSummary}. Start or restart one from the Vulnerable Apps panel.`
              : "No platform-managed vulnerable app is currently running. Only apps deployed through the dashboard's Deploy App flow count for Red-agent startup."}
          </p>
        ) : null}
        {error ? <p className="error-banner">{error}</p> : null}
      </div>

      <div className="action-row red-agent-actions">
        <button className="primary-button" type="button" disabled={startDisabled} onClick={onOpenStart}>
          Start Experiment Run
        </button>
        <button className="ghost-button" type="button" onClick={onOpenSessions}>
          View Sessions
        </button>
        <button className="ghost-button" type="button" disabled={stopDisabled} onClick={onStop}>
          {isStopping ? "Stopping..." : "Stop Red Agent"}
        </button>
      </div>

      <p className="helper-copy">
        Use the start button to open the session setup dialog, configure the experiment, and launch both Blue and Red under the same run identifier.
      </p>

      {evidenceUrl ? (
        <div className="artifact-preview">
          <div className="panel-header">
            <h2>{isPageAnalysisEvidence ? "Page Analysis Screenshot" : "Latest Screenshot"}</h2>
            <p className="panel-copy">
              {isPageAnalysisEvidence
                ? "First page captured before LLM scenario applicability analysis."
                : "Latest Red Playwright artifact for the active or most recent run."}
            </p>
          </div>
          <a href={`${API_BASE_URL}${evidenceUrl}`} target="_blank" rel="noreferrer">
            <img
              src={`${API_BASE_URL}${evidenceUrl}`}
              alt={isPageAnalysisEvidence ? "Page analysis screenshot" : "Latest Red agent screenshot"}
              className="artifact-image"
            />
          </a>
          <p className="helper-copy artifact-path">
            {evidencePath}
          </p>
        </div>
      ) : null}

      <RedAgentTerminal
        logs={logs}
        streamState={streamState}
      />
    </section>
  );
}
