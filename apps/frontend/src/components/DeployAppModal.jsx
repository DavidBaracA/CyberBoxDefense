import { useState } from "react";

const fallbackTemplates = [
  {
    template_id: "juice_shop",
    display_name: "OWASP Juice Shop",
    description: "Modern intentionally vulnerable web application.",
    default_port: 3000,
    caveat: "",
  },
  {
    template_id: "dvwa",
    display_name: "DVWA",
    description: "Classic Damn Vulnerable Web Application.",
    default_port: 8080,
    caveat: "First launch may require setup in the browser.",
  },
  {
    template_id: "crapi",
    display_name: "OWASP crAPI",
    description: "API-focused multi-container target.",
    default_port: 8888,
    caveat: "Current MVP may require additional local compose assets.",
  },
];

const initialForm = {
  name: "",
  template_id: "juice_shop",
  port: "3000",
};

export default function DeployAppModal({
  isOpen,
  onClose,
  onDeploy,
  isSubmitting,
  error,
  templates,
}) {
  const [form, setForm] = useState(initialForm);
  const availableTemplates = Array.isArray(templates) && templates.length > 0 ? templates : fallbackTemplates;
  const selectedTemplate =
    availableTemplates.find((template) => template.template_id === form.template_id) ||
    availableTemplates[0];

  if (!isOpen) {
    return null;
  }

  function handleChange(event) {
    const { name, value } = event.target;
    if (name === "template_id") {
      const nextTemplate =
        availableTemplates.find((template) => template.template_id === value) || availableTemplates[0];
      setForm((current) => ({
        ...current,
        template_id: value,
        port: String(nextTemplate?.default_port || current.port),
      }));
      return;
    }
    setForm((current) => ({ ...current, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    await onDeploy({
      ...form,
      port: Number(form.port),
    });
    setForm(initialForm);
  }

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div className="modal-card panel" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <div>
            <p className="eyebrow">Operator Action</p>
            <h2>Deploy Vulnerable App</h2>
          </div>
          <button className="ghost-button" type="button" onClick={onClose}>
            Close
          </button>
        </div>

        <form className="deploy-form" onSubmit={handleSubmit}>
          <label className="form-field">
            <span>Name</span>
            <input
              name="name"
              value={form.name}
              onChange={handleChange}
              placeholder="Target A"
              required
            />
          </label>

          <label className="form-field">
            <span>Template</span>
            <select name="template_id" value={form.template_id} onChange={handleChange}>
              {availableTemplates.map((template) => (
                <option key={template.template_id} value={template.template_id}>
                  {template.display_name}
                </option>
              ))}
            </select>
          </label>

          <div className="template-note">
            <strong>{selectedTemplate?.display_name || "Template"}</strong>
            <p className="panel-copy">{selectedTemplate?.description || "No template description available."}</p>
            {selectedTemplate?.caveat ? (
              <p className="warning-copy">Note: {selectedTemplate.caveat}</p>
            ) : null}
            {selectedTemplate?.status_notes ? (
              <p className="panel-copy">{selectedTemplate.status_notes}</p>
            ) : null}
          </div>

          <label className="form-field">
            <span>Port</span>
            <input
              name="port"
              type="number"
              min="1"
              max="65535"
              value={form.port}
              onChange={handleChange}
              required
            />
          </label>

          {error ? <p className="error-banner">{error}</p> : null}

          <div className="form-actions">
            <button className="ghost-button" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="primary-button" type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Deploying..." : "Deploy App"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
