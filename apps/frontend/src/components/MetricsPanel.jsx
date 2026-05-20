function formatMetric(value, suffix = "") {
  if (value === null || value === undefined || value === "") {
    return "N/A";
  }

  if (typeof value === "number") {
    return `${value.toFixed(3)}${suffix}`;
  }

  return `${value}${suffix}`;
}

export default function MetricsPanel({ metrics }) {
  const snapshot = metrics && typeof metrics === "object" ? metrics : {};
  const red = snapshot.red || {};
  const blue = snapshot.blue || {};
  const overall = snapshot.overall || {};

  return (
    <section className="panel metrics-panel">
      <div className="panel-header">
        <h2>Evaluation Metrics</h2>
        <p className="panel-copy">
          Aggregate metrics split by Red activity, Blue detections, and overall evaluation.
        </p>
      </div>

      <div className="metrics-agent-grid">
        <div className="metrics-section">
          <h3>Red Agent</h3>
          <div className="metrics-list">
            <div className="metric-row">
              <span>Evaluated Attacks</span>
              <strong>{formatMetric(red.evaluated_attack_count ?? snapshot.attack_ground_truth_count)}</strong>
            </div>
            <div className="metric-row">
              <span>Detected Attacks</span>
              <strong>{formatMetric(red.detected_attack_count)}</strong>
            </div>
            <div className="metric-row">
              <span>Missed Attacks</span>
              <strong>{formatMetric(red.missed_attack_count)}</strong>
            </div>
            <div className="metric-row">
              <span>Ground Truth Records</span>
              <strong>{formatMetric(red.ground_truth_record_count)}</strong>
            </div>
          </div>
        </div>

        <div className="metrics-section">
          <h3>Blue Agent</h3>
          <div className="metrics-list">
            <div className="metric-row">
              <span>Detections</span>
              <strong>{formatMetric(blue.detection_count ?? snapshot.detection_count)}</strong>
            </div>
            <div className="metric-row">
              <span>Matched Detections</span>
              <strong>{formatMetric(blue.matched_detection_count)}</strong>
            </div>
            <div className="metric-row">
              <span>False Positives</span>
              <strong>{formatMetric(blue.false_positive_count)}</strong>
            </div>
            <div className="metric-row">
              <span>False Positive Rate</span>
              <strong>{formatMetric(blue.false_positive_rate ?? snapshot.false_positive_rate)}</strong>
            </div>
          </div>
        </div>
      </div>

      <div className="metrics-section metrics-overall-section">
        <h3>Overall</h3>
        <div className="metrics-list">
          <div className="metric-row">
            <span>Telemetry Events</span>
            <strong>{formatMetric(overall.telemetry_event_count ?? snapshot.telemetry_event_count)}</strong>
          </div>
          <div className="metric-row">
            <span>MTTD</span>
            <strong>{formatMetric(overall.mean_time_to_detection_seconds ?? snapshot.mean_time_to_detection_seconds, " s")}</strong>
          </div>
          <div className="metric-row">
            <span>Detection Accuracy</span>
            <strong>{formatMetric(overall.detection_accuracy ?? snapshot.detection_accuracy)}</strong>
          </div>
          <div className="metric-row">
            <span>Classification Accuracy</span>
            <strong>{formatMetric(overall.classification_accuracy ?? snapshot.classification_accuracy)}</strong>
          </div>
        </div>
      </div>
    </section>
  );
}
