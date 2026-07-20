import { useState } from "react";

const SHORT_LABEL = {
  input: "입력값",
  request: "요청",
  processing: "처리",
  transformation: "변환",
  result: "결과",
  vulnerable_code: "코드",
};

export default function FlowStepper({ steps }) {
  const [index, setIndex] = useState(0);
  const step = steps[index];

  return (
    <div className="flow-stepper">
      <div className="flow-tabs">
        {steps.map((s, i) => (
          <button
            key={s.step}
            type="button"
            className={"flow-tab" + (i === index ? " active" : "") + (i < index ? " done" : "")}
            onClick={() => setIndex(i)}
          >
            {SHORT_LABEL[s.step] || s.label}
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
          ← 이전
        </button>
        <span className="flow-step-count">
          {index + 1} / {steps.length}
        </span>
        <button type="button" disabled={index === steps.length - 1} onClick={() => setIndex((i) => i + 1)}>
          다음 →
        </button>
      </div>
    </div>
  );
}
