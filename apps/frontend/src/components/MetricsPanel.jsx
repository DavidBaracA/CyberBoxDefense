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

  return (
    <section className="panel metrics-panel">
      <div className="panel-header">
        <h2>Evaluation Metrics</h2>
        <p className="panel-copy">
          Minimal MVP metrics view with room for future charts and scenario timelines.
        </p>
      </div>

      <div className="metrics-list">
        <div className="metric-row">
          <span>MTTD</span>
          <strong>{formatMetric(snapshot.mean_time_to_detection_seconds, " s")}</strong>
        </div>
        <div className="metric-row">
          <span>Detection Accuracy</span>
          <strong>{formatMetric(snapshot.detection_accuracy)}</strong>
        </div>
        <div className="metric-row">
          <span>Attack Classification Accuracy</span>
          <strong>{formatMetric(snapshot.classification_accuracy)}</strong>
        </div>
        <div className="metric-row">
          <span>False Positive Rate</span>
          <strong>{formatMetric(snapshot.false_positive_rate)}</strong>
        </div>
      </div>
    </section>
  );
}
