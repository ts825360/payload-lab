import { useState } from "react";
import ServerStateView from "./ServerStateView.jsx";
import CodeView from "./CodeView.jsx";
import ProcessFlowchart from "./ProcessFlowchart.jsx";
import ExecutionGraphView from "./ExecutionGraphView.jsx";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const TAB_LABEL = { state: "서버 상태", code: "코드", process: "처리 흐름" };
const TAB_DESC = {
  state: "실제 DB·데이터 상태",
  code: "취약한 코드 원문",
  process: "요청이 처리된 순서",
};

function SuccessBanner() {
  return (
    <div className="success-banner">
      <span className="success-check" aria-hidden="true">✓</span>
      <div>
        <strong className="success-heading">공격 성공</strong>
        <span className="success-sub">이 입력이 실제로 서버에서 어떻게 처리됐는지 아래에서 확인하세요.</span>
      </div>
    </div>
  );
}

export default function AttemptResultView({ result, submittedValue, labId, category }) {
  const graph = result.execution_graph;

  // #19: 실행 그래프가 있으면 탭 없이 한 번의 스크롤(코드 → 유도 과정/관계 → 결과)로
  // 렌더한다. XSS는 그래프의 live 단계가 실제 실행 iframe을 담는다.
  if (graph) {
    return (
      <section className="result-canvas">
        <SuccessBanner />
        <ExecutionGraphView graph={graph} labId={labId} submittedValue={submittedValue} />
      </section>
    );
  }

  // 폴백: 그래프가 없는 랩은 기존 탭 뷰 유지 (현재 MVP 랩은 모두 그래프 보유).
  return <LegacyTabs result={result} submittedValue={submittedValue} labId={labId} category={category} />;
}

function LegacyTabs({ result, submittedValue, labId, category }) {
  const isLive = category === "reflected_xss";

  const tabs = [];
  if (result.server_state) tabs.push("state");
  if (result.code_snippet) tabs.push("code");
  tabs.push("process");

  const [active, setActive] = useState(tabs[0]);

  return (
    <section className="result-canvas">
      <SuccessBanner />

      {isLive && (
        <div className="live-primary">
          <div className="live-hint">
            아래는 우리 서버가 <strong>실제로 돌려준 페이지</strong>입니다 — 탭 뒤에 숨기지 않고 바로 보여드립니다. 진짜로 실행됩니다.
          </div>
          <iframe
            className="live-frame"
            sandbox="allow-scripts allow-modals"
            src={`${API_BASE}/labs/${labId}/render?query=${encodeURIComponent(submittedValue)}`}
            title="실제 실행 결과"
          />
          <div className="view-note">이 랩은 서버에 저장된 상태가 없어 "서버 상태" 대신 실제 실행 결과를 보여줍니다. 아래 탭은 보조 정보입니다.</div>
        </div>
      )}

      <div className="view-tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={t === active}
            className={"view-tab" + (t === active ? " active" : "")}
            onClick={() => setActive(t)}
          >
            <span className="view-tab-title">{TAB_LABEL[t]}</span>
            <span className="view-tab-desc">{TAB_DESC[t]}</span>
          </button>
        ))}
      </div>

      <div className="view-panel" role="tabpanel">
        {active === "state" && <ServerStateView state={result.server_state} />}
        {active === "code" && <CodeView code={result.code_snippet} />}
        {active === "process" && <ProcessFlowchart steps={result.visualization} />}
      </div>
    </section>
  );
}
