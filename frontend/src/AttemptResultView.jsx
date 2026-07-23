import ExecutionGraphView from "./ExecutionGraphView.jsx";

// 성공 화면: 배너 + 단일 스크롤 실행 다이어그램(#19). 예전 서버상태/코드/처리흐름
// 3탭은 ExecutionGraph가 대체해 은퇴했다.

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

export default function AttemptResultView({ result, submittedValue, labId }) {
  const graph = result.execution_graph;
  return (
    <section className="result-canvas">
      <SuccessBanner />
      {graph && <ExecutionGraphView graph={graph} labId={labId} submittedValue={submittedValue} />}
    </section>
  );
}
