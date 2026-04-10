import { useEffect, useMemo, useState } from "react";

import RedAgentTerminal from "./RedAgentTerminal";

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
  scenarios,
  isStarting,
  isStopping,
  error,
  onStart,
  onStop,
}) {
  const rows = Array.isArray(runningApps) ? runningApps : [];
  const scenarioRows = Array.isArray(scenarios) ? scenarios : [];
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedScenarios, setSelectedScenarios] = useState([]);
  const [validationError, setValidationError] = useState("");

  const status = state?.status || "idle";
  const isActive = status === "running" || status === "starting";
  const startDisabled =
    !rows.length || !selectedTargetId || selectedScenarios.length === 0 || isStarting || isActive;
  const stopDisabled = isStopping || !isActive;

  const activeTargetId = state?.target_app_id || "";

  useEffect(() => {
    if (isActive && activeTargetId) {
      setSelectedTargetId(activeTargetId);
    } else if (!selectedTargetId && rows.length > 0) {
      setSelectedTargetId(rows[0].app_id);
    } else if (selectedTargetId && !rows.some((app) => app.app_id === selectedTargetId)) {
      setSelectedTargetId(rows[0]?.app_id || "");
    }
  }, [rows, selectedTargetId, isActive, activeTargetId]);

  useEffect(() => {
    if (isActive && Array.isArray(state?.selected_scenarios) && state.selected_scenarios.length > 0) {
      setSelectedScenarios(state.selected_scenarios);
      return;
    }

    if (selectedScenarios.length === 0 && scenarioRows.length > 0) {
      setSelectedScenarios([scenarioRows[0].scenario_id]);
    } else {
      setSelectedScenarios((current) =>
        current.filter((scenarioId) =>
          scenarioRows.some((scenario) => scenario.scenario_id === scenarioId)
        )
      );
    }
  }, [scenarioRows, isActive, state?.selected_scenarios]);

  const scenarioMap = useMemo(
    () => new Map(scenarioRows.map((scenario) => [scenario.scenario_id, scenario])),
    [scenarioRows]
  );

  function toggleScenario(scenarioId) {
    if (isActive) {
      return;
    }
    setSelectedScenarios((current) =>
      current.includes(scenarioId)
        ? current.filter((item) => item !== scenarioId)
        : [...current, scenarioId]
    );
  }

  async function handleStart() {
    if (!selectedTargetId) {
      setValidationError("Select a running target before starting the Red agent.");
      return;
    }
    if (selectedScenarios.length === 0) {
      setValidationError("Select at least one predefined scenario.");
      return;
    }
    setValidationError("");
    await onStart({
      target_app_id: selectedTargetId,
      scenario_ids: selectedScenarios,
    });
  }

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
          <span>Ground-truth events: {state?.emitted_events_count ?? 0}</span>
        </div>
        {rows.length === 0 ? (
          <p className="warning-copy">
            At least one vulnerable app must be running before the Red agent can start.
          </p>
        ) : null}
        {validationError ? <p className="error-banner">{validationError}</p> : null}
        {error ? <p className="error-banner">{error}</p> : null}
      </div>

      <div className="selection-grid">
        <label className="control-field">
          <span className="field-label">Target App</span>
          <select
            value={selectedTargetId}
            onChange={(event) => setSelectedTargetId(event.target.value)}
            disabled={isActive || rows.length === 0}
          >
            {rows.length === 0 ? <option value="">No running targets</option> : null}
            {rows.map((app) => (
              <option key={app.app_id} value={app.app_id}>
                {app.name} ({app.template_display_name || app.template_id})
              </option>
            ))}
          </select>
        </label>

        <div className="control-field">
          <span className="field-label">Bounded Scenarios</span>
          <div className="scenario-checklist">
            {scenarioRows.map((scenario) => (
              <label key={scenario.scenario_id} className="scenario-option">
                <input
                  type="checkbox"
                  checked={selectedScenarios.includes(scenario.scenario_id)}
                  onChange={() => toggleScenario(scenario.scenario_id)}
                  disabled={isActive}
                />
                <span>
                  <strong>{scenario.display_name}</strong>
                  <small>{scenario.description || scenarioMap.get(scenario.scenario_id)?.notes}</small>
                </span>
              </label>
            ))}
          </div>
        </div>
      </div>

      <div className="action-row red-agent-actions">
        <button className="primary-button" type="button" disabled={startDisabled} onClick={handleStart}>
          {isStarting ? "Starting..." : "Start Red Agent"}
        </button>
        <button className="ghost-button" type="button" disabled={stopDisabled} onClick={onStop}>
          {isStopping ? "Stopping..." : "Stop Red Agent"}
        </button>
      </div>

      <p className="helper-copy">
        Red-agent runtime output is operator-only. Ground truth is stored separately and is not exposed in Blue runtime views.
      </p>

      <RedAgentTerminal logs={logs} streamState={streamState} />
    </section>
  );
}
