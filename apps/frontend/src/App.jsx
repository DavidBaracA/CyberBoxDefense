import { useEffect, useState } from "react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const emptySnapshot = {
  observability: [],
  detections: [],
  ground_truth: [],
  metrics: {
    mean_time_to_detection_seconds: null,
    detection_accuracy: 0,
    classification_accuracy: 0,
    false_positive_rate: 0,
    attack_count: 0,
    detection_count: 0,
    observable_event_count: 0,
  },
};

function MetricCard({ label, value }) {
  return (
    <div className="metric-card">
      <span className="metric-label">{label}</span>
      <strong className="metric-value">{value}</strong>
    </div>
  );
}

function TimelineTable({ title, rows, columns }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>{title}</h2>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key}>{column.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length}>No data yet.</td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={row.id}>
                  {columns.map((column) => (
                    <td key={column.key}>{row[column.key] ?? "-"}</td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function App() {
  const [snapshot, setSnapshot] = useState(emptySnapshot);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchSnapshot = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/dashboard`);
        if (!response.ok) {
          throw new Error(`Dashboard request failed with ${response.status}`);
        }
        const data = await response.json();
        setSnapshot(data);
        setError("");
      } catch (err) {
        setError(err.message);
      }
    };

    fetchSnapshot();
    const intervalId = window.setInterval(fetchSnapshot, 3000);
    return () => window.clearInterval(intervalId);
  }, []);

  const telemetryRows = snapshot.observability.map((event) => ({
    id: event.event_id,
    timestamp: new Date(event.timestamp).toLocaleTimeString(),
    source: event.source,
    message: event.message,
    status: event.http_status ?? "-",
  }));

  const detectionRows = snapshot.detections.map((detection) => ({
    id: detection.detection_id,
    timestamp: new Date(detection.timestamp).toLocaleTimeString(),
    detector: detection.detector,
    classification: detection.predicted_attack_type,
    confidence: detection.confidence,
  }));

  const attackRows = snapshot.ground_truth.map((attack) => ({
    id: attack.attack_id,
    timestamp: new Date(attack.timestamp).toLocaleTimeString(),
    attack_type: attack.attack_type,
    target: attack.target,
    status: attack.status,
  }));

  return (
    <main className="app-shell">
      <section className="hero panel">
        <p className="eyebrow">MSc Thesis Prototype</p>
        <h1>CyberBoxDefense</h1>
        <p className="hero-copy">
          Local cyber-range dashboard for indirect observability, Blue detections,
          offline attack ground truth, and first-pass evaluation metrics.
        </p>
        {error ? <p className="error-banner">{error}</p> : null}
      </section>

      <section className="metrics-grid">
        <MetricCard
          label="Observable Events"
          value={snapshot.metrics.observable_event_count}
        />
        <MetricCard label="Detections" value={snapshot.metrics.detection_count} />
        <MetricCard label="Attacks" value={snapshot.metrics.attack_count} />
        <MetricCard
          label="MTTD (s)"
          value={
            snapshot.metrics.mean_time_to_detection_seconds === null
              ? "N/A"
              : snapshot.metrics.mean_time_to_detection_seconds.toFixed(2)
          }
        />
        <MetricCard
          label="Detection Accuracy"
          value={snapshot.metrics.detection_accuracy}
        />
        <MetricCard
          label="False Positive Rate"
          value={snapshot.metrics.false_positive_rate}
        />
      </section>

      <div className="dashboard-grid">
        <TimelineTable
          title="Observability Timeline"
          rows={telemetryRows}
          columns={[
            { key: "timestamp", label: "Time" },
            { key: "source", label: "Source" },
            { key: "message", label: "Message" },
            { key: "status", label: "HTTP" },
          ]}
        />
        <TimelineTable
          title="Blue Detections"
          rows={detectionRows}
          columns={[
            { key: "timestamp", label: "Time" },
            { key: "detector", label: "Detector" },
            { key: "classification", label: "Class" },
            { key: "confidence", label: "Confidence" },
          ]}
        />
      </div>

      <TimelineTable
        title="Offline Ground Truth"
        rows={attackRows}
        columns={[
          { key: "timestamp", label: "Time" },
          { key: "attack_type", label: "Attack" },
          { key: "target", label: "Target" },
          { key: "status", label: "Status" },
        ]}
      />
    </main>
  );
}
