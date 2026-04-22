function formatTimestamp(value) {
  if (!value) {
    return "Unknown time";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleTimeString();
}

export default function TelemetryList({ items }) {
  const rows = Array.isArray(items) ? items : [];

  return (
    <section className="panel stream-panel telemetry-panel">
      <div className="panel-header">
        <h2>Telemetry Stream</h2>
        <p className="panel-copy">
          Blue-safe indirect observability only. No ground-truth attacker actions are shown here.
        </p>
      </div>

      <div className="stream-list telemetry-stream-list">
        {rows.length === 0 ? (
          <p className="empty-state">No telemetry events available yet.</p>
        ) : (
          rows.map((item, index) => (
            <article className="stream-item" key={item.event_id || `${item.timestamp}-${index}`}>
              <div className="stream-topline">
                <span className="pill">{item.kind || item.event_type || "unknown"}</span>
                <span className="stream-time">{formatTimestamp(item.timestamp)}</span>
              </div>
              <p className="stream-message">{item.message || "No message provided."}</p>
              <div className="stream-meta">
                <span>Source: {item.source || "unknown"}</span>
                <span>Service: {item.service_name || item.container_name || "unknown"}</span>
                <span>HTTP: {item.http_status ?? "N/A"}</span>
              </div>
            </article>
          ))
        )}
      </div>
    </section>
  );
}
