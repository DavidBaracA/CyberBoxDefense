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

export default function RedAgentPanel({
  state,
  logs,
  streamState,
  runningApps,
  isStopping,
  error,
  onOpenStart,
  onOpenSessions,
  onStop,
}) {
  const rows = Array.isArray(runningApps) ? runningApps : [];

  const status = state?.status || "idle";
  const isActive = status === "running" || status === "starting"; 
  const startDisabled = !rows.length || isActive;
  const stopDisabled = isStopping || !isActive;

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
            At least one vulnerable app must be running before the Red agent can start.
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

      {state?.latest_artifact_url ? (
        <div className="artifact-preview">
          <div className="panel-header">
            <h2>Latest Screenshot</h2>
            <p className="panel-copy">
              Latest Red Playwright artifact for the active or most recent run.
            </p>
          </div>
          <a href={`${API_BASE_URL}${state.latest_artifact_url}`} target="_blank" rel="noreferrer">
            <img
              src={`${API_BASE_URL}${state.latest_artifact_url}`}
              alt="Latest Red agent screenshot"
              className="artifact-image"
            />
          </a>
          <p className="helper-copy artifact-path">
            {state.latest_artifact_path}
          </p>
        </div>
      ) : null}

      <RedAgentTerminal logs={logs} streamState={streamState} />
    </section>
  );
}
