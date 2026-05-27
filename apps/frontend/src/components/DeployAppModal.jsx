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
  use_custom_image: false,
  custom_image_name: "",
  container_port: "",
  target_path: "/",
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
    if (name === "use_custom_image") {
      setForm((current) => ({
        ...current,
        use_custom_image: event.target.checked,
      }));
      return;
    }
    setForm((current) => ({ ...current, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    const payload = form.use_custom_image
      ? {
          name: form.name,
          template_id: "custom",
          custom_image_name: form.custom_image_name,
          target_path: form.target_path || "/",
          port: Number(form.port),
        }
      : {
          name: form.name,
          template_id: form.template_id,
          port: Number(form.port),
        };
    if (form.use_custom_image && form.container_port) {
      payload.container_port = Number(form.container_port);
    }
    await onDeploy(payload);
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
            <select
              name="template_id"
              value={form.template_id}
              onChange={handleChange}
              disabled={form.use_custom_image}
            >
              {availableTemplates.map((template) => (
                <option key={template.template_id} value={template.template_id}>
                  {template.display_name}
                </option>
              ))}
            </select>
          </label>

          {!form.use_custom_image ? (
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
          ) : null}

          <label className="checkbox-field">
            <input
              name="use_custom_image"
              type="checkbox"
              checked={form.use_custom_image}
              onChange={handleChange}
            />
            <span>Use custom Docker image</span>
          </label>

          {form.use_custom_image ? (
            <div className="template-note custom-image-fields">
              <label className="form-field">
                <span>Docker image</span>
                <input
                  name="custom_image_name"
                  value={form.custom_image_name}
                  onChange={handleChange}
                  placeholder="my-app:latest"
                  required={form.use_custom_image}
                />
              </label>

              <label className="form-field">
                <span>Internal app port</span>
                <input
                  name="container_port"
                  type="number"
                  min="1"
                  max="65535"
                  value={form.container_port}
                  onChange={handleChange}
                  placeholder="Auto-detect"
                />
              </label>

              <label className="form-field">
                <span>App path</span>
                <input
                  name="target_path"
                  value={form.target_path}
                  onChange={handleChange}
                  placeholder="/"
                />
              </label>
            </div>
          ) : null}

          <label className="form-field">
            <span>Monitored proxy port</span>
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
