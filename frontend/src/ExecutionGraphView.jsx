import { useState } from "react";

// #19 실행 다이어그램. 서버가 내려준 execution_graph를 한 번의 스크롤로 렌더한다.
// shape="derivation": 문자열이 단계별로 변형되는 유도 과정(SQLi/XSS).
// shape="relational": 객체가 화살표로 연결되는 관계 스냅샷(IDOR).
// 상호 하이라이트는 "공유 group id" 하나로(어디에 hover/focus해도 같은 group 전체가 켜짐).

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
const ROLE_STYLE = { breakout: "taint", logic: "taint", injected: "taint", comment: "comment" };

export default function ExecutionGraphView({ graph, labId, submittedValue }) {
  const [active, setActive] = useState(null);

  if (!graph || !graph.steps) return null;

  function grouped(text, group, extraCls, key) {
    if (!group) return <span key={key} className={extraCls}>{text}</span>;
    const on = active === group;
    return (
      <span
        key={key}
        tabIndex={0}
        data-group={group}
        className={`grp ${extraCls}${on ? " hl" : ""}`}
        onMouseEnter={() => setActive(group)}
        onMouseLeave={() => setActive(null)}
        onFocus={() => setActive(group)}
        onBlur={() => setActive(null)}
      >
        {text}
      </span>
    );
  }

  function relBox(obj) {
    if (!obj) return null;
    return (
      <div className={`rel-box tone-${obj.tone || "neutral"}`}>
        <div className="rel-box-title">{obj.title}</div>
        {obj.subtitle && <div className="rel-box-sub">{obj.subtitle}</div>}
      </div>
    );
  }

  function renderStep(step) {
    if (step.kind === "query") {
      return (
        <div className="deriv-body" key={step.id}>
          {step.label && <div className="deriv-label">{step.label}</div>}
          <div className="deriv-query">
            {step.spans.map((sp, i) => grouped(sp.text, sp.group, `qs${sp.style ? " qs-" + sp.style : ""}`, i))}
          </div>
          {step.note && <div className="deriv-note">{step.note}</div>}
        </div>
      );
    }
    if (step.kind === "split") {
      return (
        <div className="deriv-body" key={step.id}>
          {step.label && <div className="deriv-label">{step.label}</div>}
          <div className="deriv-split">
            {step.conditions.map((c, i) => (
              <div className="cond" key={i}>
                {grouped(c.text, c.group, "cond-text", `c${i}`)}
                {c.result && <span className={"cond-result" + (c.result === "언제나 참" ? " on" : "")}>{c.result}</span>}
              </div>
            ))}
            {step.op && <div className="split-op">— {step.op}: 하나만 참이면 참 —</div>}
          </div>
          {step.note && <div className="deriv-note">{step.note}</div>}
        </div>
      );
    }
    if (step.kind === "table") {
      return (
        <div className="deriv-body" key={step.id}>
          {step.label && <div className="deriv-label">{step.label}</div>}
          <table className="deriv-table">
            <thead>
              <tr>{step.columns.map((c) => <th key={c}>{c}</th>)}</tr>
            </thead>
            <tbody>
              {step.rows.map((r, i) => (
                <tr key={i} className={r.matched ? "matched" : ""}>
                  {r.cells.map((cell, j) => <td key={j}>{cell}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
          {step.note && <div className="deriv-note">{step.note}</div>}
        </div>
      );
    }
    if (step.kind === "boundary") {
      return (
        <div className="deriv-body" key={step.id}>
          <div className="deriv-boundary">
            <span className="deriv-boundary-label">{step.label}</span>
          </div>
          {step.note && <div className="deriv-note">{step.note}</div>}
        </div>
      );
    }
    if (step.kind === "live") {
      return (
        <div className="deriv-body" key={step.id}>
          {step.label && <div className="deriv-label">{step.label}</div>}
          <iframe
            className="deriv-live-frame"
            sandbox="allow-scripts allow-modals"
            src={`${API_BASE}/labs/${labId}/render?query=${encodeURIComponent(submittedValue || "")}`}
            title="실제 실행 결과"
          />
          {step.note && <div className="deriv-note">{step.note}</div>}
        </div>
      );
    }
    if (step.kind === "note") {
      return (
        <div className="deriv-body" key={step.id}>
          {step.label && <div className="deriv-label">{step.label}</div>}
          <div className={"deriv-note-box" + (step.style === "missing" ? " missing" : "")}>{step.note}</div>
        </div>
      );
    }
    if (step.kind === "relations") {
      const byId = Object.fromEntries(step.objects.map((o) => [o.id, o]));
      return (
        <div className="deriv-body" key={step.id}>
          {step.label && <div className="deriv-label">{step.label}</div>}
          <div className="rel-graph">
            {step.arrows.map((a, i) => (
              <div className={`rel-row tone-${a.tone || "neutral"}`} key={i}>
                {relBox(byId[a.source])}
                <div className="rel-arrow">
                  {a.label && <span className="rel-arrow-label">{a.label}</span>}
                  <span className="rel-arrow-line" aria-hidden="true">→</span>
                </div>
                {relBox(byId[a.target])}
              </div>
            ))}
          </div>
          {step.note && <div className="deriv-note">{step.note}</div>}
        </div>
      );
    }
    if (step.kind === "verdict") {
      return (
        <div className="deriv-body" key={step.id}>
          <div className={"deriv-verdict" + (step.status === "success" ? " success" : "")}>
            <span className="deriv-verdict-mark" aria-hidden="true">✓</span>
            {step.text}
          </div>
        </div>
      );
    }
    return null;
  }

  return (
    <div className="exec-graph">
      {graph.payload_segments.length > 0 && (
        <div className="exec-payload">
          <span className="exec-payload-label">페이로드</span>
          {graph.payload_segments.map((s) =>
            grouped(s.text, s.id, `seg${ROLE_STYLE[s.role] ? " seg-" + ROLE_STYLE[s.role] : ""}`, s.id),
          )}
        </div>
      )}

      {graph.code.length > 0 && (
        <div className="exec-code">
          <div className="exec-code-cap">{graph.code_caption || "취약한 코드"}</div>
          <pre className="exec-code-body">
            {graph.code.map((c, i) => grouped(c.text, c.group, "cs", i))}
          </pre>
        </div>
      )}

      <ol className="deriv-chain">
        {graph.steps.map((step, i) => (
          <li className={"deriv-node" + (step.kind === "boundary" ? " is-boundary" : "")} key={step.id}>
            <div className="deriv-rail" aria-hidden="true">
              <span className={"deriv-dot" + (step.kind === "verdict" ? " done" : "") + (step.style === "missing" ? " missing" : "")} />
              {i < graph.steps.length - 1 && <span className="deriv-line" />}
            </div>
            {renderStep(step)}
          </li>
        ))}
      </ol>
    </div>
  );
}
