import { useState } from "react";

export default function LensUnderline({ payloadText, message, checklist }) {
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
          {checklist && checklist.length > 0 && (
            <div className="lens-checklist">
              {checklist.map((line, i) => (
                <div key={i} className="checklist-item">
                  {line}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </span>
  );
}
