import { useEffect, useState } from "react";
import { fetchLabs, attemptLab } from "./api.js";
import AttemptResultView from "./AttemptResultView.jsx";
import LensInput from "./LensInput.jsx";
import Sidebar from "./Sidebar.jsx";
import ThemeToggle from "./ThemeToggle.jsx";

export const CATEGORIES = [
  {
    id: "sql_injection",
    label: "SQL Injection",
    tag: "SQLi",
    field: "username",
    // 각 랩이 흉내내는 "진짜 웹 기능"을 사용자에게 명시 (스펙의 practice-first 원칙)
    scenario: "실제 로그인 폼입니다. 비밀번호를 몰라도 admin 계정으로 로그인해 보세요.",
    fieldLabel: "아이디 입력란",
    placeholder: { easy: "admin' OR '1'='1' --", medium: "admin' oR '1'='1' --" },
  },
  {
    id: "reflected_xss",
    label: "Reflected XSS",
    tag: "XSS",
    field: "query",
    scenario: "실제 검색 기능입니다. 검색어가 결과 페이지에 그대로 되비칩니다.",
    fieldLabel: "검색어",
    placeholder: { easy: "<script>alert(1)</script>", medium: "<ScRiPt>alert(1)</script>" },
  },
  {
    id: "idor",
    label: "IDOR",
    tag: "IDOR",
    field: "requested_id",
    numeric: true,
    scenario: "실제 주문 조회 기능입니다. 내 주문번호를 남의 것으로 바꿔 보세요.",
    fieldLabel: "주문번호",
    placeholder: { easy: "1043", medium: "1043" },
    extraFields: {
      medium: [{ name: "claimed_user_id", label: "claimed_user_id (소유자로 위장)", placeholder: "2001", numeric: true }],
    },
  },
];

function labId(categoryId, difficulty) {
  return `${categoryId.replace(/_/g, "-")}-${difficulty}`;
}

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") || "dark");
  const [labs, setLabs] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [difficulty, setDifficulty] = useState("easy");
  const [inputValue, setInputValue] = useState("");
  const [extraValues, setExtraValues] = useState({});
  const [result, setResult] = useState(null);
  const [submittedValue, setSubmittedValue] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  useEffect(() => {
    fetchLabs().then(setLabs).catch((e) => setError(e.message));
  }, []);

  const labsById = Object.fromEntries(labs.map((l) => [l.id, l]));

  function resetAttempt() {
    setInputValue("");
    setExtraValues({});
    setResult(null);
    setSubmittedValue(null);
    setError(null);
  }

  function selectCategory(categoryId) {
    setSelectedCategory(categoryId);
    resetAttempt();
  }

  function selectDifficulty(d) {
    setDifficulty(d);
    resetAttempt();
  }

  function isDifficultyAvailable(categoryId, d) {
    return Boolean(labsById[labId(categoryId, d)]);
  }

  const activeCategory = CATEGORIES.find((c) => c.id === selectedCategory);
  const activeLab = selectedCategory ? labsById[labId(selectedCategory, difficulty)] : null;
  const extraFields = activeCategory?.extraFields?.[difficulty] || [];

  async function submitAttempt(e) {
    e.preventDefault();
    const value = activeCategory.numeric ? Number(inputValue) : inputValue;
    const payload = { [activeCategory.field]: value };
    for (const f of extraFields) {
      const raw = extraValues[f.name] ?? "";
      payload[f.name] = f.numeric ? Number(raw) : raw;
    }
    try {
      const res = await attemptLab(activeLab.id, payload);
      setResult(res);
      setSubmittedValue(inputValue);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="brand-name">Payload<span className="brand-accent">Lab</span></span>
        </div>
        <div className="safety-chip" role="note">
          <span className="safety-dot" aria-hidden="true" />
          실습 전용 · 로컬에서만 실행
        </div>
        <ThemeToggle theme={theme} onToggle={() => setTheme(theme === "dark" ? "light" : "dark")} />
      </header>

      <div className="safety-strip">
        ⚠️ 이 앱은 <strong>의도적으로 취약하게</strong> 만들어졌습니다. 로컬 Docker 환경에서만 실행하고,
        외부에 공개하거나 여기서 배운 기법을 실제 서비스에 시도하지 마세요.
      </div>

      <div className="main-layout">
        <Sidebar
          categories={CATEGORIES}
          selectedCategory={selectedCategory}
          onSelectCategory={selectCategory}
          difficulty={difficulty}
          onSelectDifficulty={selectDifficulty}
          isDifficultyAvailable={(d) => !selectedCategory || isDifficultyAvailable(selectedCategory, d)}
        />

        <main className="content">
          {error && <p className="error-text">{error}</p>}

          {!selectedCategory && (
            <div className="empty-state">
              <div className="empty-lens" aria-hidden="true" />
              <h1 className="empty-title">공격을 넣고, 왜 됐는지·왜 안 됐는지 본다</h1>
              <p className="empty-sub">
                왼쪽에서 공격 유형을 고르세요. 성공하면 입력이 서버에서 어떻게 처리됐는지 다이어그램으로,
                실패하면 어떤 조건이 빠졌는지 <span className="lens-word">Lens</span>가 짚어줍니다.
              </p>
            </div>
          )}

          {selectedCategory && !activeLab && (
            <p className="hint">{activeCategory.label} ({difficulty === "easy" ? "Easy" : "Medium"})는 아직 준비되지 않았습니다.</p>
          )}

          {selectedCategory && activeLab && (
            <div className="workbench">
              <div className="lab-head">
                <div className="lab-head-top">
                  <h1 className="lab-title">{activeCategory.label}</h1>
                  <span className={`diff-chip diff-${difficulty}`}>{difficulty === "easy" ? "Easy" : "Medium"}</span>
                  <span className="lab-tag">{activeCategory.tag}</span>
                </div>
                <p className="lab-scenario">{activeCategory.scenario}</p>
              </div>

              <form className="attempt-form" onSubmit={submitAttempt}>
                <label className="field-label" htmlFor="payload-input">{activeCategory.fieldLabel}</label>
                <div className="input-group">
                  <LensInput
                    id="payload-input"
                    value={inputValue}
                    onChange={(e) => {
                      setInputValue(e.target.value);
                      if (result) setResult(null);
                    }}
                    placeholder={activeCategory.placeholder[difficulty]}
                    failed={Boolean(result && !result.success)}
                    lensMessage={result?.lens_message}
                    lensSteps={result?.lens_steps}
                  />
                </div>

                {extraFields.map((f) => (
                  <div className="extra-field" key={f.name}>
                    <label className="field-label" htmlFor={`extra-${f.name}`}>{f.label}</label>
                    <input
                      id={`extra-${f.name}`}
                      className="text-input"
                      placeholder={f.placeholder}
                      value={extraValues[f.name] ?? ""}
                      onChange={(e) => {
                        setExtraValues((prev) => ({ ...prev, [f.name]: e.target.value }));
                        if (result) setResult(null);
                      }}
                    />
                  </div>
                ))}

                <button className="submit-btn" type="submit">시도하기</button>
              </form>

              {result && result.success && (
                <AttemptResultView
                  key={submittedValue}
                  result={result}
                  submittedValue={submittedValue}
                  labId={activeLab.id}
                  category={activeCategory.id}
                />
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
