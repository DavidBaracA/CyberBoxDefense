import BlueAgentTerminal from "./BlueAgentTerminal";

function StatusBadge({ status }) {
  const normalized = status || "idle";
  return (
    <span className={`status-badge blue-status-badge is-${normalized}`}>
      <span className="status-dot" />
      {normalized}
    </span>
  );
}

export default function BlueAgentPanel({
  state,
  logs,
  streamState,
  hasRunningTarget,
  isStarting,
  isStopping,
  error,
  onStart,
  onStop,
}) {
  const status = state?.status || "idle";
  const startDisabled =
    !hasRunningTarget || isStarting || status === "running" || status === "starting";
  const stopDisabled = isStopping || (status !== "running" && status !== "starting");

  return (
    <section className="panel blue-agent-panel">
      <div className="panel-header panel-header-row">
        <div>
          <h2>Blue Agent</h2>
          <p className="panel-copy">
            Runtime control and Blue-safe terminal output based only on indirect observables.
          </p>
        </div>
        <StatusBadge status={status} />
      </div>

      <div className="blue-agent-meta">
        <p className="panel-copy">{state?.message || "Blue agent is idle."}</p>
        <div className="blue-agent-runtime-details">
          <span>Terminal stream: {streamState || "connecting"}</span>
          <span>Target: {state?.selected_target || "None selected"}</span>
          <span>Cycles: {state?.iteration_count ?? 0}</span>
          <span>
            Latest inference: {state?.predicted_attack_type || "No classification yet"}
          </span>
          <span>
            Confidence:{" "}
            {typeof state?.confidence === "number" ? state.confidence.toFixed(2) : "N/A"}
          </span>
        </div>
        {!hasRunningTarget ? (
          <p className="warning-copy">
            At least one vulnerable app must be running before the Blue agent can start.
          </p>
        ) : null}
        {error ? <p className="error-banner">{error}</p> : null}
      </div>

      <div className="action-row blue-agent-actions">
        <button className="primary-button" type="button" disabled={startDisabled} onClick={onStart}>
          {isStarting ? "Starting..." : "Start Blue Agent"}
        </button>
        <button className="ghost-button" type="button" disabled={stopDisabled} onClick={onStop}>
          {isStopping ? "Stopping..." : "Stop Blue Agent"}
        </button>
      </div>

      <BlueAgentTerminal logs={logs} streamState={streamState} />
    </section>
  );
}
