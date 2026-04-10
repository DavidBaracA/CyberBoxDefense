import { useEffect, useRef } from "react";

function formatLinePrefix(entry) {
  const timestamp = entry?.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : "--:--:--";
  const level = (entry?.level || "info").toUpperCase();
  return `[${timestamp}] ${level}`;
}

export default function RedAgentTerminal({ logs, streamState }) {
  const rows = Array.isArray(logs) ? logs : [];
  const containerRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) {
      return;
    }
    containerRef.current.scrollTop = containerRef.current.scrollHeight;
  }, [rows.length]);

  return (
    <div className="blue-terminal" ref={containerRef}>
      <div className="terminal-connection">WebSocket: {streamState || "connecting"}</div>
      {rows.length === 0 ? (
        <div className="terminal-line is-muted">No Red-agent runtime output yet.</div>
      ) : (
        rows.map((entry, index) => (
          <div className="terminal-line" key={`${entry.timestamp || "line"}-${index}`}>
            <span className="terminal-prefix">{formatLinePrefix(entry)}</span>{" "}
            <span>{entry?.message || "No message available."}</span>
          </div>
        ))
      )}
    </div>
  );
}

