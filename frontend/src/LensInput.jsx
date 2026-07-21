import { useState } from "react";

const STATUS_ICON = { passed: "✓", failed: "✕", unknown: "–" };

export default function LensInput({ value, onChange, placeholder, failed, lensMessage, lensSteps }) {
  const [pinned, setPinned] = useState(false);
  const open = failed && pinned;

  return (
    <div className="lens-input-wrapper">
      <div className="input-row">
        <input
          className={failed ? "input-failed" : ""}
          placeholder={placeholder}
          value={value}
          onChange={onChange}
        />
        {failed && (
          <button type="button" className="lens-reveal-btn" onClick={() => setPinned((p) => !p)}>
            왜 실패했나요?
          </button>
        )}
      </div>
      {open && (
        <div className="lens-popover-inline">
          <div className="lens-message">{lensMessage}</div>
          {lensSteps && lensSteps.length > 0 && (
            <div className="lens-stepper">
              {lensSteps.map((step, i) => (
                <div className={`lens-step lens-step-${step.status}`} key={i}>
                  <span className="dot">{STATUS_ICON[step.status]}</span>
                  <span className="text">{step.description}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
