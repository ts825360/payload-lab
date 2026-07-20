import { useState } from "react";
import ServerStateView from "./ServerStateView.jsx";
import CodeView from "./CodeView.jsx";
import ProcessNarrative from "./ProcessNarrative.jsx";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const TAB_LABEL = { state: "서버 상태", code: "코드", live: "실행 결과", process: "처리 흐름" };

export default function AttemptResultView({ result, submittedValue, labId, category }) {
  const tabs = [];
  if (result.server_state) tabs.push("state");
  if (category === "reflected_xss") tabs.push("live");
  if (result.code_snippet) tabs.push("code");
  tabs.push("process");

  const [active, setActive] = useState(tabs[0]);

  return (
    <div>
      <strong className="success-heading">성공! 공격이 통했습니다.</strong>

      <div className="view-tabs">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            className={"view-tab" + (t === active ? " active" : "")}
            onClick={() => setActive(t)}
          >
            {TAB_LABEL[t]}
          </button>
        ))}
      </div>

      <div className="view-panel">
        {active === "state" && <ServerStateView state={result.server_state} />}
        {active === "code" && <CodeView code={result.code_snippet} />}
        {active === "live" && (
          <div>
            <div className="live-hint">아래는 우리 서버가 실제로 돌려준 페이지입니다 — 진짜로 실행됩니다.</div>
            <iframe
              className="live-frame"
              sandbox="allow-scripts allow-modals"
              src={`${API_BASE}/labs/${labId}/render?query=${encodeURIComponent(submittedValue)}`}
              title="실제 실행 결과"
            />
          </div>
        )}
        {active === "process" && <ProcessNarrative steps={result.visualization} />}
      </div>
    </div>
  );
}
