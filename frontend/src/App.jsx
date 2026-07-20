import { useEffect, useState } from "react";
import { fetchLabs, attemptLab } from "./api.js";
import AttemptResultView from "./AttemptResultView.jsx";

const FIELD_CONFIG = {
  sql_injection: { field: "username", label: "아이디", placeholder: "admin' OR '1'='1' --" },
  reflected_xss: { field: "query", label: "검색어", placeholder: "<script>alert(1)</script>" },
  idor: { field: "requested_id", label: "주문 번호 (숫자)", placeholder: "1043", numeric: true },
};

export default function App() {
  const [labs, setLabs] = useState([]);
  const [selected, setSelected] = useState(null);
  const [inputValue, setInputValue] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchLabs().then(setLabs).catch((e) => setError(e.message));
  }, []);

  function selectLab(lab) {
    setSelected(lab);
    setInputValue("");
    setResult(null);
    setError(null);
  }

  async function submitAttempt(e) {
    e.preventDefault();
    const config = FIELD_CONFIG[selected.category];
    const value = config.numeric ? Number(inputValue) : inputValue;
    try {
      const res = await attemptLab(selected.id, { [config.field]: value });
      setResult(res);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div>
      <div className="warning-banner">
        ⚠️ 이 앱은 의도적으로 취약하게 만들어졌습니다. 로컬 Docker 환경에서만 실행하세요.
        외부에 공개하거나, 여기서 배운 기법을 실제 서비스에 시도하지 마세요.
      </div>

      <h1>PayloadLab</h1>

      {error && <p style={{ color: "#f85149" }}>{error}</p>}

      {!selected && (
        <ul className="lab-list">
          {labs.map((lab) => (
            <li key={lab.id}>
              <button onClick={() => selectLab(lab)}>
                {lab.name} — {lab.difficulty}
              </button>
            </li>
          ))}
        </ul>
      )}

      {selected && (
        <div>
          <button className="back-link" onClick={() => setSelected(null)}>
            ← 목록으로
          </button>
          <h2>{selected.name}</h2>
          <form className="attempt-form" onSubmit={submitAttempt}>
            <input
              placeholder={FIELD_CONFIG[selected.category].placeholder}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
            />
            <button type="submit">시도</button>
          </form>
          {result && <AttemptResultView result={result} />}
        </div>
      )}
    </div>
  );
}
