export default function AttemptResultView({ result }) {
  if (result.success) {
    return (
      <div className="result-success">
        <strong>성공! 공격이 통했습니다.</strong>
        {result.visualization.map((step) => (
          <div className="viz-step" key={step.step}>
            <div className="label">{step.label}</div>
            <div className="value">{step.value}</div>
            {step.note && <div className="note">💡 {step.note}</div>}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="result-fail">
      <strong>실패: {result.lens_message}</strong>
      {result.lens_checklist && (
        <div style={{ marginTop: "0.75rem" }}>
          {result.lens_checklist.map((line, i) => (
            <div className="checklist-item" key={i}>
              {line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
