export default function SummaryCard({ label, value, detail }) {
  return (
    <article className="summary-card">
      <p className="summary-label">{label}</p>
      <strong className="summary-value">{value ?? "N/A"}</strong>
      <p className="summary-detail">{detail || "No additional context yet."}</p>
    </article>
  );
}
