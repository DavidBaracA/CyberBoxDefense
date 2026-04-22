import { useEffect, useMemo, useRef, useState } from "react";

const emptyConfig = {};

export default function ExperimentRunModal({
  isOpen,
  onClose,
  onStart,
  isSubmitting,
  error,
  runningApps,
  scenarios,
  runFormConfig,
}) {
  const rows = Array.isArray(runningApps) ? runningApps : [];
  const scenarioRows = Array.isArray(scenarios) ? scenarios : [];
  const durationOptions = Array.isArray(runFormConfig?.duration_options)
    ? runFormConfig.duration_options
    : [];
  const attackDepthOptions = Array.isArray(runFormConfig?.attack_depths)
    ? runFormConfig.attack_depths
    : [];
  const blueModeOptions = Array.isArray(runFormConfig?.blue_modes)
    ? runFormConfig.blue_modes
    : [];
  const redModelOptions = Array.isArray(runFormConfig?.red_models)
    ? runFormConfig.red_models
    : [];
  const defaultConfig = runFormConfig?.default_config || emptyConfig;

  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedScenarios, setSelectedScenarios] = useState([]);
  const [durationSeconds, setDurationSeconds] = useState("");
  const [tryAllAvailable, setTryAllAvailable] = useState(false);
  const [attackDepth, setAttackDepth] = useState("balanced");
  const [stopOnFirstConfirmed, setStopOnFirstConfirmed] = useState(false);
  const [blueMode, setBlueMode] = useState("detect_only");
  const [redModelId, setRedModelId] = useState("gemma3:4b");
  const [validationError, setValidationError] = useState("");
  const wasOpenRef = useRef(false);

  useEffect(() => {
    const justOpened = isOpen && !wasOpenRef.current;
    wasOpenRef.current = isOpen;

    if (!justOpened) {
      return;
    }

    setSelectedTargetId(rows[0]?.app_id || "");
    setSelectedScenarios(
      scenarioRows.length > 0 ? [scenarioRows[0].scenario_id] : []
    );
    setDurationSeconds(
      String(defaultConfig.duration_seconds || durationOptions[0]?.value || "600")
    );
    setTryAllAvailable(Boolean(defaultConfig.try_all_available ?? false));
    setAttackDepth(defaultConfig.attack_depth || attackDepthOptions[0]?.value || "balanced");
    setStopOnFirstConfirmed(
      Boolean(defaultConfig.stop_on_first_confirmed_vulnerability ?? false)
    );
    setBlueMode(defaultConfig.blue_mode || blueModeOptions[0]?.value || "detect_only");
    setRedModelId(defaultConfig.red_model_id || redModelOptions[0]?.value || "gemma3:4b");
    setValidationError("");
  }, [
    isOpen,
    rows,
    scenarioRows,
    defaultConfig,
    durationOptions,
    attackDepthOptions,
    blueModeOptions,
    redModelOptions,
  ]);

  const selectedDurationOption = useMemo(
    () => durationOptions.find((option) => option.value === durationSeconds),
    [durationOptions, durationSeconds]
  );

  if (!isOpen) {
    return null;
  }

  function toggleScenario(scenarioId) {
    setSelectedScenarios((current) =>
      current.includes(scenarioId)
        ? current.filter((item) => item !== scenarioId)
        : [...current, scenarioId]
    );
  }

  async function handleSubmit(event) {
    event.preventDefault();

    if (!selectedTargetId) {
      setValidationError("Select a running target before starting the session.");
      return;
    }
    if (!tryAllAvailable && selectedScenarios.length === 0) {
      setValidationError("Select at least one vulnerability scenario to try.");
      return;
    }

    setValidationError("");
    await onStart({
      target_app_id: selectedTargetId,
      scenario_ids: selectedScenarios,
      config: {
        duration_seconds: Number(durationSeconds || defaultConfig.duration_seconds || 600),
        enabled_attack_types: selectedScenarios,
        try_all_available: tryAllAvailable,
        attack_depth: attackDepth || defaultConfig.attack_depth || "balanced",
        stop_on_first_confirmed_vulnerability: stopOnFirstConfirmed,
        blue_mode: blueMode || defaultConfig.blue_mode || "detect_only",
        red_model_id: redModelId || defaultConfig.red_model_id || "gemma3:4b",
        graceful_shutdown_seconds: defaultConfig.graceful_shutdown_seconds ?? 10,
      },
    });
  }

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="modal-card panel experiment-run-modal"
        role="dialog"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-header">
          <div>
            <p className="eyebrow">Experiment Setup</p>
            <h2>Start Session</h2>
            <p className="panel-copy">
              Configure the session, then start both Blue and Red under the same run.
            </p>
          </div>
          <button className="ghost-button" type="button" onClick={onClose}>
            x
          </button>
        </div>

        <form className="deploy-form" onSubmit={handleSubmit}>
          <label className="form-field">
            <span>Target App</span>
            <select
              value={selectedTargetId}
              onChange={(event) => setSelectedTargetId(event.target.value)}
              disabled={rows.length === 0 || isSubmitting}
            >
              {rows.length === 0 ? <option value="">No running targets</option> : null}
              {rows.map((app) => (
                <option key={app.app_id} value={app.app_id}>
                  {app.name} ({app.template_display_name || app.template_id})
                </option>
              ))}
            </select>
          </label>

          <div className="selection-grid experiment-config-grid">
            <label className="form-field">
              <span>Session Duration</span>
              <select
                value={durationSeconds}
                onChange={(event) => setDurationSeconds(event.target.value)}
                disabled={isSubmitting}
              >
                {durationOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              {selectedDurationOption?.description ? (
                <small className="helper-copy">{selectedDurationOption.description}</small>
              ) : null}
            </label>

            <label className="form-field">
              <span>Attack Depth</span>
              <select
                value={attackDepth}
                onChange={(event) => setAttackDepth(event.target.value)}
                disabled={isSubmitting}
              >
                {attackDepthOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="form-field">
              <span>Blue Mode</span>
              <select
                value={blueMode}
                onChange={(event) => setBlueMode(event.target.value)}
                disabled={isSubmitting}
              >
                {blueModeOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="form-field">
              <span>Red Planning Model</span>
              <select
                value={redModelId}
                onChange={(event) => setRedModelId(event.target.value)}
                disabled={isSubmitting}
              >
                {redModelOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="toggle-field">
              <input
                type="checkbox"
                checked={tryAllAvailable}
                onChange={(event) => setTryAllAvailable(event.target.checked)}
                disabled={isSubmitting}
              />
              <span>
                <strong>Try all available</strong>
                <small className="helper-copy">
                  Use every available scenario from the backend catalog for this session.
                </small>
              </span>
            </label>

            <label className="toggle-field">
              <input
                type="checkbox"
                checked={stopOnFirstConfirmed}
                onChange={(event) => setStopOnFirstConfirmed(event.target.checked)}
                disabled={isSubmitting}
              />
              <span>
                <strong>Stop on first confirmed vulnerability</strong>
                <small className="helper-copy">
                  End the run as soon as a vulnerability signal is confirmed.
                </small>
              </span>
            </label>
          </div>

          <div className="form-field">
            <span>Vulnerability Scenarios</span>
            {tryAllAvailable ? (
              <p className="helper-copy">
                All available scenarios will be included automatically.
              </p>
            ) : null}
            <div className="scenario-checklist">
              {scenarioRows.map((scenario) => (
                <label key={scenario.scenario_id} className="scenario-option">
                  <input
                    type="checkbox"
                    checked={selectedScenarios.includes(scenario.scenario_id)}
                    onChange={() => toggleScenario(scenario.scenario_id)}
                    disabled={isSubmitting || tryAllAvailable}
                  />
                  <span>
                    <strong>{scenario.display_name}</strong>
                    <small>
                      {scenario.description}
                      {scenario.notes ? ` ${scenario.notes}` : ""}
                    </small>
                  </span>
                </label>
              ))}
            </div>
          </div>

          {rows.length === 0 ? (
            <p className="warning-copy">
              At least one vulnerable app must be running before a session can start.
            </p>
          ) : null}
          {validationError ? <p className="error-banner">{validationError}</p> : null}
          {error ? <p className="error-banner">{error}</p> : null}

          <div className="form-actions">
            <button className="ghost-button" type="button" onClick={onClose}>
              Cancel
            </button>
            <button
              className="primary-button"
              type="submit"
              disabled={isSubmitting || rows.length === 0}
            >
              {isSubmitting ? "Starting..." : "Start Experiment Run"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
