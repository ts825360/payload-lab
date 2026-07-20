import { useState } from "react";

const SHORT_LABEL = {
  input: "입력값",
  request: "요청",
  processing: "처리",
  transformation: "변환",
  result: "결과",
  vulnerable_code: "코드",
};

const STEP_ICON = {
  input: "🧑",
  request: "📨",
  processing: "⚙️",
  transformation: "🔀",
  result: "💥",
  vulnerable_code: "📄",
};

function HighlightedValue({ value, payload }) {
  const needle = payload === null || payload === undefined ? "" : String(payload);
  if (!needle) return value;
  const idx = value.indexOf(needle);
  if (idx === -1) return value;
  return (
    <>
      {value.slice(0, idx)}
      <mark className="payload-highlight">{needle}</mark>
      {value.slice(idx + needle.length)}
    </>
  );
}

export default function FlowStepper({ steps, payload }) {
  const [index, setIndex] = useState(0);
  const step = steps[index];

  return (
    <div className="flow-stepper">
      <div className="flow-pipeline">
        {steps.map((s, i) => (
          <span className="flow-pipeline-item" key={s.step}>
            <button
              type="button"
              className={"flow-node-btn" + (i === index ? " active" : "") + (i < index ? " done" : "")}
              onClick={() => setIndex(i)}
              title={s.label}
            >
              <span className="flow-icon">{STEP_ICON[s.step] || "•"}</span>
              <span className="flow-node-label">{SHORT_LABEL[s.step] || s.label}</span>
            </button>
            {i < steps.length - 1 && <span className="flow-arrow-inline">→</span>}
          </span>
        ))}
      </div>

      <div className="flow-node">
        <div className="label">{step.label}</div>
        <div className="value">
          <HighlightedValue value={step.value} payload={payload} />
        </div>
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
