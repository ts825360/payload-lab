export default function ProcessFlowchart({ steps }) {
  return (
    <div className="flowchart">
      {steps.map((s, i) => (
        <div key={s.step}>
          <div className="flowchart-node">
            <div className="flowchart-label">{s.label}</div>
            <div className="flowchart-value">{s.value}</div>
            {s.note && <div className="note">💡 {s.note}</div>}
          </div>
          {i < steps.length - 1 && <div className="flowchart-arrow">↓</div>}
        </div>
      ))}
    </div>
  );
}
