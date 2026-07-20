import { useState } from "react";

const STATUS_ICON = { passed: "✓", failed: "✕", unknown: "–" };

export default function LensUnderline({ payloadText, message, steps }) {
  const [pinned, setPinned] = useState(false);
  const [hovering, setHovering] = useState(false);
  const open = pinned || hovering;

  return (
    <span className="lens-wrapper">
      <span
        className="lens-underline"
        onClick={() => setPinned((p) => !p)}
        onMouseEnter={() => setHovering(true)}
        onMouseLeave={() => setHovering(false)}
      >
        {payloadText}
      </span>
      {open && (
        <div className="lens-popover">
          <div className="lens-message">{message}</div>
          {steps && steps.length > 0 && (
            <div className="lens-stepper">
              {steps.map((step, i) => (
                <div className={`lens-step lens-step-${step.status}`} key={i}>
                  <span className="dot">{STATUS_ICON[step.status]}</span>
                  <span className="text">{step.description}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </span>
  );
}
