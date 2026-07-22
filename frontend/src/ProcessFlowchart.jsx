// step 이름별로 노드 성격(색)을 나눈다: 입력=사용자, 결과=성공, 취약코드=위험
const STEP_KIND = {
  input: "user",
  request: "flow",
  processing: "flow",
  transformation: "flow",
  result: "success",
  vulnerable_code: "danger",
};

export default function ProcessFlowchart({ steps }) {
  return (
    <ol className="flowchart">
      {steps.map((s, i) => (
        <li className={`flow-node flow-${STEP_KIND[s.step] || "flow"}`} key={s.step}>
          <div className="flow-rail" aria-hidden="true">
            <span className="flow-dot" />
            {i < steps.length - 1 && <span className="flow-line" />}
          </div>
          <div className="flow-body">
            <div className="flow-label">{s.label}</div>
            <div className="flow-value">{s.value}</div>
            {s.note && <div className="note">💡 {s.note}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}
