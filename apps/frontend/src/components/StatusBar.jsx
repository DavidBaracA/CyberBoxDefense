function ConnectionBadge({ ok, label }) {
  return (
    <span className={`status-badge ${ok ? "is-online" : "is-offline"}`}>
      <span className="status-dot" />
      {label || "Unknown"}
    </span>
  );
}

export default function StatusBar({ title, subtitle, connection, lastUpdated }) {
  const updatedLabel = lastUpdated
    ? new Date(lastUpdated).toLocaleTimeString()
    : "Waiting for first refresh";

  return (
    <header className="status-bar panel">
      <div>
        <p className="eyebrow">Controlled Cyber Range</p>
        <h1>{title}</h1>
        <p className="hero-copy">{subtitle}</p>
      </div>
      <div className="status-meta">
        <ConnectionBadge ok={connection?.ok} label={connection?.label} />
        <p className="muted-copy">Backend: {connection?.path || "endpoint not resolved yet"}</p>
        <p className="muted-copy">Last refresh: {updatedLabel}</p>
      </div>
    </header>
  );
}
