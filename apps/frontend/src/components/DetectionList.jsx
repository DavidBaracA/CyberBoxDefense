function formatTimestamp(value) {
  if (!value) {
    return "Unknown time";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleTimeString();
}

function formatConfidence(value) {
  return typeof value === "number" ? `${Math.round(value * 100)}%` : "N/A";
}

export default function DetectionList({ items }) {
  const rows = Array.isArray(items) ? items : [];

  return (
    <section className="panel stream-panel">
      <div className="panel-header">
        <h2>Detection Stream</h2>
        <p className="panel-copy">
          Blue outputs inferred from indirect telemetry, ready for future experiment timelines.
        </p>
      </div>

      {rows.length === 0 ? (
        <p className="empty-state">No detections available yet.</p>
      ) : (
        <div className="stream-list">
          {rows.map((item, index) => (
            <article
              className="stream-item detection-item"
              key={item.detection_id || `${item.timestamp}-${index}`}
            >
              <div className="stream-topline">
                <span className="pill warning-pill">
                  {item.classification || item.predicted_attack_type || "unclassified"}
                </span>
                <span className="stream-time">{formatTimestamp(item.timestamp)}</span>
              </div>
              <p className="stream-message">{item.summary || "No detection summary provided."}</p>
              <div className="stream-meta">
                <span>Detector: {item.detector || "unknown"}</span>
                <span>Confidence: {formatConfidence(item.confidence)}</span>
                <span>
                  Evidence: {Array.isArray(item.evidence_event_ids) ? item.evidence_event_ids.length : 0}
                </span>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
