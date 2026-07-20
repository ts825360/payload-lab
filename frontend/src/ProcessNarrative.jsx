export default function ProcessNarrative({ steps }) {
  return (
    <div className="process-narrative">
      {steps.map((s) => (
        <div className="narrative-row" key={s.step}>
          <span className="narrative-label">{s.label}:</span> <span className="narrative-value">{s.value}</span>
          {s.note && <div className="note">💡 {s.note}</div>}
        </div>
      ))}
    </div>
  );
}
