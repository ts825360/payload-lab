import { useState } from "react";
import ServerStateView from "./ServerStateView.jsx";
import CodeView from "./CodeView.jsx";
import ProcessFlowchart from "./ProcessFlowchart.jsx";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const TAB_LABEL = { state: "서버 상태", code: "코드", process: "처리 흐름" };
const TAB_DESC = {
  state: "실제 DB/데이터 상태",
  code: "취약한 코드 원문",
  process: "요청이 처리된 순서",
};

export default function AttemptResultView({ result, submittedValue, labId, category }) {
  const isLive = category === "reflected_xss";

  const tabs = [];
  if (result.server_state) tabs.push("state");
  if (result.code_snippet) tabs.push("code");
  tabs.push("process");

  const [active, setActive] = useState(tabs[0]);

  return (
    <div>
      <strong className="success-heading">성공! 공격이 통했습니다.</strong>

      {isLive && (
        <div className="live-primary">
          <div className="live-hint">
            아래는 우리 서버가 실제로 돌려준 페이지입니다 — 탭 뒤에 숨기지 않고 바로 보여드립니다. 진짜로 실행됩니다.
          </div>
          <iframe
            className="live-frame"
            sandbox="allow-scripts allow-modals"
            src={`${API_BASE}/labs/${labId}/render?query=${encodeURIComponent(submittedValue)}`}
            title="실제 실행 결과"
          />
          <div className="view-note">이 랩은 서버에 저장된 상태가 없어 "서버 상태" 탭 대신 실제 실행 결과를 보여줍니다. 아래 탭은 보조 정보입니다.</div>
        </div>
      )}

      <div className="view-tabs">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            className={"view-tab" + (t === active ? " active" : "")}
            onClick={() => setActive(t)}
          >
            <span className="view-tab-title">{TAB_LABEL[t]}</span>
            <span className="view-tab-desc">{TAB_DESC[t]}</span>
          </button>
        ))}
      </div>

      <div className="view-panel">
        {active === "state" && <ServerStateView state={result.server_state} />}
        {active === "code" && <CodeView code={result.code_snippet} />}
        {active === "process" && <ProcessFlowchart steps={result.visualization} />}
      </div>
    </div>
  );
}
