import { useState } from "react";

export default function FlowStepper({ steps }) {
  const [index, setIndex] = useState(0);
  const step = steps[index];

  return (
    <div className="flow-stepper">
      <div className="flow-progress">
        {steps.map((s, i) => (
          <button
            key={s.step}
            type="button"
            className={"flow-dot" + (i === index ? " active" : "") + (i < index ? " done" : "")}
            onClick={() => setIndex(i)}
            title={s.label}
          >
            {i + 1}
          </button>
        ))}
      </div>

      <div className="flow-node">
        <div className="label">{step.label}</div>
        <div className="value">{step.value}</div>
        {step.note && <div className="note">💡 {step.note}</div>}
      </div>

      <div className="flow-controls">
        <button type="button" disabled={index === 0} onClick={() => setIndex((i) => i - 1)}>
          ← 이전 단계
        </button>
        <span className="flow-step-count">
          {index + 1} / {steps.length}
        </span>
        <button type="button" disabled={index === steps.length - 1} onClick={() => setIndex((i) => i + 1)}>
          다음 단계 →
        </button>
      </div>
    </div>
  );
}
