import { useEffect, useRef, useState } from "react";

const STATUS_ICON = { passed: "✓", failed: "✕", unknown: "–" };

// 빈 입력으로 실패해도 밑줄이 사라지지 않도록 최소 폭을 보장한다.
// (이게 없으면 폭이 0이 돼 hover 대상이 없어지고 Lens 진단에 도달할 수 없다.)
const MIN_UNDERLINE_WIDTH = 28;

let measureCanvas;
function measureTextWidth(text, font) {
  measureCanvas = measureCanvas || document.createElement("canvas");
  const ctx = measureCanvas.getContext("2d");
  // canvas 2d를 못 쓰는 환경(jsdom 등)에서는 글자 수 기반으로 근사한다.
  if (!ctx || typeof ctx.measureText !== "function") return text.length * 8;
  ctx.font = font;
  return ctx.measureText(text).width;
}

export default function LensInput({ id, value, onChange, placeholder, failed, lensMessage, lensSteps }) {
  const [hovering, setHovering] = useState(false);
  const [focused, setFocused] = useState(false);
  const inputRef = useRef(null);
  const [mark, setMark] = useState({ left: 0, width: 0 });
  // hover(마우스)뿐 아니라 focus(키보드/터치)로도 열리게 해서 모든 입력 방식에서
  // Lens 진단에 도달할 수 있게 한다.
  const open = failed && (hovering || focused);

  useEffect(() => {
    if (!failed || !inputRef.current) return;
    const el = inputRef.current;
    const cs = getComputedStyle(el);
    const font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
    setMark({
      left: parseFloat(cs.paddingLeft) || 0,
      // 실제 입력한 글자 수만큼만 밑줄을 긋되, 빈 입력에서도 hover 대상이 남도록
      // 최소 폭을 보장한다.
      width: Math.max(measureTextWidth(value, font), MIN_UNDERLINE_WIDTH),
    });
  }, [value, failed]);

  return (
    <div className="lens-input-wrapper">
      <div className="input-row">
        <input
          id={id}
          ref={inputRef}
          className={"text-input payload-input" + (failed ? " input-failed" : "")}
          placeholder={placeholder}
          value={value}
          onChange={onChange}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          aria-invalid={failed || undefined}
          aria-describedby={open ? "lens-popover" : undefined}
        />
        {failed && (
          <span
            className="underline-mark"
            style={{ left: mark.left, width: mark.width }}
            onMouseEnter={() => setHovering(true)}
            onMouseLeave={() => setHovering(false)}
          />
        )}
      </div>
      {failed && !open && (
        <p className="lens-nudge">밑줄에 마우스를 올리거나 입력란을 클릭하면 <span className="lens-word">Lens</span>가 이유를 알려줍니다.</p>
      )}
      {open && (
        <div className="lens-popover-inline" id="lens-popover" role="status">
          <div className="lens-popover-title">
            <span className="lens-glyph" aria-hidden="true" />
            왜 실패했나요?
          </div>
          <div className="lens-message">{lensMessage}</div>
          {lensSteps && lensSteps.length > 0 && (
            <ol className="lens-stepper">
              {lensSteps.map((step, i) => (
                <li className={`lens-step lens-step-${step.status}`} key={i}>
                  <span className="dot">{STATUS_ICON[step.status]}</span>
                  <span className="text">{step.description}</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </div>
  );
}
