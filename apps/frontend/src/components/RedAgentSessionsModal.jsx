import { useEffect, useState } from "react";

import {
  API_BASE_URL,
  getRedAgentSessionDetail,
  getRedAgentSessions,
} from "../services/api";

function formatDateTime(value) {
  if (!value) {
    return "Not available";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat("sv-SE", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(parsed);
}

function SectionHeading({ title, copy }) {
  return (
    <div className="panel-header">
      <h3>{title}</h3>
      {copy ? <p className="panel-copy">{copy}</p> : null}
    </div>
  );
}

function ScreenshotGallery({ screenshots }) {
  const rows = Array.isArray(screenshots) ? screenshots : [];
  const [selectedScreenshotId, setSelectedScreenshotId] = useState(rows[0]?.screenshot_id || "");

  useEffect(() => {
    setSelectedScreenshotId(rows[0]?.screenshot_id || "");
  }, [rows]);

  if (rows.length === 0) {
    return <p className="empty-state">No screenshots were captured for this session.</p>;
  }

  const selected = rows.find((item) => item.screenshot_id === selectedScreenshotId) || rows[0];

  return (
    <div className="session-gallery">
      <a
        className="session-gallery-preview"
        href={`${API_BASE_URL}${selected.artifact_url}`}
        target="_blank"
        rel="noreferrer"
      >
        <img src={`${API_BASE_URL}${selected.artifact_url}`} alt={selected.filename} />
      </a>
      <p className="helper-copy">
        {selected.filename} • {formatDateTime(selected.captured_at)}
      </p>
      {selected.summary ? <p className="panel-copy">{selected.summary}</p> : null}

      <div className="session-gallery-grid">
        {rows.map((screenshot) => (
          <button
            key={screenshot.screenshot_id}
            className={`session-gallery-thumb ${selected.screenshot_id === screenshot.screenshot_id ? "is-selected" : ""}`}
            type="button"
            onClick={() => setSelectedScreenshotId(screenshot.screenshot_id)}
          >
            <img
              src={`${API_BASE_URL}${screenshot.artifact_url}`}
              alt={screenshot.filename}
            />
            <span>{screenshot.scenario_name || screenshot.filename}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function VulnerabilityList({ vulnerabilities }) {
  const rows = Array.isArray(vulnerabilities) ? vulnerabilities : [];

  if (rows.length === 0) {
    return <p className="empty-state">No confirmed vulnerabilities were stored for this session.</p>;
  }

  return (
    <div className="session-vulnerability-list">
      {rows.map((item) => (
        <article key={item.vulnerability_id} className="session-vulnerability-card">
          <div className="session-vulnerability-header">
            <div>
              <strong>{item.title}</strong>
              <p className="panel-copy">{item.type}</p>
            </div>
            <span className={`status-badge session-severity-badge is-${String(item.severity || "").toLowerCase()}`}>
              {item.severity || "unknown"}
            </span>
          </div>
          <p><strong>Location:</strong> {item.location || "Not available"}</p>
          <p><strong>Discovered:</strong> {formatDateTime(item.discovered_at)}</p>
          <p><strong>Evidence:</strong> {item.evidence || "No evidence stored."}</p>
        </article>
      ))}
    </div>
  );
}

function SessionDetail({ detail }) {
  if (!detail) {
    return <p className="empty-state">Select a completed session to inspect its details.</p>;
  }

  const metadataEntries = Object.entries(detail.metadata || {}).filter(([, value]) => value !== null && value !== undefined && value !== "");

  return (
    <div className="session-detail">
      <div className="session-detail-summary">
        <div className="session-summary-grid">
          <div>
            <span className="session-summary-label">Started</span>
            <strong>{formatDateTime(detail.started_at)}</strong>
          </div>
          <div>
            <span className="session-summary-label">Ended</span>
            <strong>{formatDateTime(detail.ended_at)}</strong>
          </div>
          <div>
            <span className="session-summary-label">Target</span>
            <strong>{detail.target_name || detail.target_app_id || "Unknown target"}</strong>
          </div>
          <div>
            <span className="session-summary-label">Target URL</span>
            <strong>{detail.target_url || "Not available"}</strong>
          </div>
        </div>

        {detail.summary ? <p className="panel-copy">{detail.summary}</p> : null}
      </div>

      <SectionHeading title="Vulnerabilities" copy="Confirmed findings captured during the completed Red-agent session." />
      <VulnerabilityList vulnerabilities={detail.vulnerabilities} />

      <SectionHeading title="Screenshots" copy="Click a screenshot to preview it larger or open it in a new tab." />
      <ScreenshotGallery screenshots={detail.screenshots} />

      <SectionHeading title="Session Metadata" copy="Lightweight operator-facing metadata persisted by the backend." />
      {metadataEntries.length === 0 ? (
        <p className="empty-state">No additional metadata was stored for this session.</p>
      ) : (
        <div className="session-metadata-grid">
          {metadataEntries.map(([key, value]) => (
            <div key={key} className="session-metadata-item">
              <span className="session-summary-label">{key}</span>
              <strong>{typeof value === "string" ? value : JSON.stringify(value)}</strong>
            </div>
          ))}
        </div>
      )}

      <SectionHeading title="Runtime Logs" copy="Buffered Red-agent logs captured while the session was running." />
      {Array.isArray(detail.logs) && detail.logs.length > 0 ? (
        <div className="blue-terminal session-log-terminal">
          {detail.logs.map((entry, index) => (
            <p key={`${entry.timestamp}-${index}`} className="terminal-line">
              <span className="terminal-prefix">[{formatDateTime(entry.timestamp)}] {entry.level}</span>{" "}
              {entry.message}
            </p>
          ))}
        </div>
      ) : (
        <p className="empty-state">No session logs were persisted for this run.</p>
      )}
    </div>
  );
}

export default function RedAgentSessionsModal({ isOpen, onClose }) {
  // TODO: Add session search/filter and pagination if the operator history grows.
  // TODO: Replace the preview-only screenshot workflow with a richer lightbox/export flow if needed.
  const [sessions, setSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [selectedSession, setSelectedSession] = useState(null);
  const [isLoadingList, setIsLoadingList] = useState(false);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!isOpen) {
      return undefined;
    }

    let isActive = true;
    setIsLoadingList(true);
    setError("");

    getRedAgentSessions()
      .then((items) => {
        if (!isActive) {
          return;
        }
        setSessions(items);
        const nextSessionId = items[0]?.session_id || "";
        setSelectedSessionId(nextSessionId);
        if (!nextSessionId) {
          setSelectedSession(null);
        }
      })
      .catch((fetchError) => {
        if (!isActive) {
          return;
        }
        setError(fetchError.message);
        setSessions([]);
        setSelectedSessionId("");
        setSelectedSession(null);
      })
      .finally(() => {
        if (isActive) {
          setIsLoadingList(false);
        }
      });

    return () => {
      isActive = false;
    };
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen || !selectedSessionId) {
      return undefined;
    }

    let isActive = true;
    setIsLoadingDetail(true);
    setError("");
    setSelectedSession(null);

    getRedAgentSessionDetail(selectedSessionId)
      .then((detail) => {
        if (isActive) {
          setSelectedSession(detail);
        }
      })
      .catch((fetchError) => {
        if (isActive) {
          setError(fetchError.message);
          setSelectedSession(null);
        }
      })
      .finally(() => {
        if (isActive) {
          setIsLoadingDetail(false);
        }
      });

    return () => {
      isActive = false;
    };
  }, [isOpen, selectedSessionId]);

  if (!isOpen) {
    return null;
  }

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="modal-card panel red-sessions-modal"
        role="dialog"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-header">
          <div>
            <p className="eyebrow">Operator Review</p>
            <h2>Select Session</h2>
            <p className="panel-copy">
              Review completed Red-agent sessions without exposing ground-truth details in the Blue runtime panel.
            </p>
          </div>
          <button className="ghost-button" type="button" onClick={onClose}>
            Close
          </button>
        </div>

        {error ? <p className="error-banner">{error}</p> : null}

        <div className="red-sessions-layout">
          <aside className="red-sessions-sidebar">
            <SectionHeading title="Completed Sessions" copy="Newest sessions appear first." />
            {isLoadingList ? <p className="empty-state">Loading completed sessions...</p> : null}
            {!isLoadingList && sessions.length === 0 ? (
              <p className="empty-state">No completed Red-agent sessions are available yet.</p>
            ) : null}
            <div className="red-session-list">
              {sessions.map((session) => (
                <button
                  key={session.session_id}
                  className={`red-session-list-item ${selectedSessionId === session.session_id ? "is-selected" : ""}`}
                  type="button"
                  onClick={() => setSelectedSessionId(session.session_id)}
                >
                  <div className="red-session-list-heading">
                    <strong>{formatDateTime(session.started_at)}</strong>
                    {session.is_latest ? <span className="status-badge">Latest Session</span> : null}
                  </div>
                  <p className="panel-copy">
                    {session.target_name || session.target_url || "Unknown target"}
                  </p>
                  <p className="helper-copy">
                    {session.vulnerability_count} vulnerabilities • {session.screenshot_count} screenshots
                  </p>
                </button>
              ))}
            </div>
          </aside>

          <section className="red-sessions-content">
            {isLoadingDetail ? (
              <p className="empty-state">Loading session details...</p>
            ) : (
              <SessionDetail detail={selectedSession} />
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
