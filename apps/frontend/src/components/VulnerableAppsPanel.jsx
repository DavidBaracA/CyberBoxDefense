function ActionButton({ children, onClick, disabled = false, tone = "default" }) {
  return (
    <button
      type="button"
      className={`table-action ${tone === "danger" ? "is-danger" : ""}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}

function renderStatus(status) {
  return status || "unknown";
}

function canStop(status) {
  return status === "running";
}

function canRestart(status) {
  return status === "running" || status === "stopped" || status === "error";
}

function canRemove(status) {
  return status !== "removed";
}

export default function VulnerableAppsPanel({
  apps,
  templates,
  isLoading,
  isActing,
  error,
  onOpenDeploy,
  onStop,
  onRestart,
  onRemove,
}) {
  const rows = Array.isArray(apps) ? apps : [];
  const templateMap = new Map(
    (Array.isArray(templates) ? templates : []).map((template) => [template.template_id, template])
  );

  return (
    <section className="panel vulnerable-apps-panel">
      <div className="panel-header panel-header-row">
        <div>
          <h2>Vulnerable Apps</h2>
          <p className="panel-copy">
            Operator-only target lifecycle management for predefined local templates.
          </p>
        </div>
        <button className="primary-button" type="button" onClick={onOpenDeploy}>
          Deploy App
        </button>
      </div>

      {error ? <p className="error-banner">{error}</p> : null}

      {isLoading ? (
        <p className="empty-state">Loading vulnerable apps...</p>
      ) : rows.length === 0 ? (
        <p className="empty-state">No vulnerable apps deployed yet.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Template</th>
                <th>Status</th>
                <th>Port</th>
                <th>Target URL</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((app) => (
                <tr key={app.app_id}>
                  <td>{app.name || "Unnamed"}</td>
                  <td>
                    {app.template_display_name ||
                      templateMap.get(app.template_id)?.display_name ||
                      app.template_id ||
                      "unknown"}
                  </td>
                  <td>{renderStatus(app.status)}</td>
                  <td>{app.port ?? "N/A"}</td>
                  <td>
                    {app.target_url ? (
                      <a href={app.target_url} target="_blank" rel="noreferrer">
                        {app.target_url}
                      </a>
                    ) : (
                      "N/A"
                    )}
                  </td>
                  <td>
                    <div className="action-row">
                      {canStop(app.status) ? (
                        <ActionButton disabled={isActing} onClick={() => onStop(app.app_id)}>
                          Stop
                        </ActionButton>
                      ) : null}
                      {canRestart(app.status) ? (
                        <ActionButton disabled={isActing} onClick={() => onRestart(app.app_id)}>
                          Restart
                        </ActionButton>
                      ) : null}
                      {canRemove(app.status) ? (
                        <ActionButton tone="danger" disabled={isActing} onClick={() => onRemove(app.app_id)}>
                          Remove
                        </ActionButton>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
