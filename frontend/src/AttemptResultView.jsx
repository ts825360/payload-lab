import LensUnderline from "./LensUnderline.jsx";

export default function AttemptResultView({ result, submittedValue }) {
  if (result.success) {
    return (
      <div>
        <strong className="success-heading">성공! 공격이 통했습니다.</strong>
        <div className="flow-diagram">
          {result.visualization.map((step, i) => (
            <div key={step.step}>
              <div className="flow-node">
                <div className="label">{step.label}</div>
                <div className="value">{step.value}</div>
                {step.note && <div className="note">💡 {step.note}</div>}
              </div>
              {i < result.visualization.length - 1 && <div className="flow-arrow">↓</div>}
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="lens-result">
      <span className="lens-result-label">제출한 값: </span>
      <LensUnderline
        payloadText={String(submittedValue)}
        message={result.lens_message}
        steps={result.lens_steps}
      />
      <div className="lens-hint">밑줄 친 부분을 클릭(또는 마우스를 올려)하면 이유를 볼 수 있습니다.</div>
    </div>
  );
}
