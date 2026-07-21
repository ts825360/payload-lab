import { useEffect, useState } from "react";
import { fetchLabs, attemptLab } from "./api.js";
import AttemptResultView from "./AttemptResultView.jsx";
import LensInput from "./LensInput.jsx";
import Sidebar from "./Sidebar.jsx";

export const CATEGORIES = [
  {
    id: "sql_injection",
    label: "SQL Injection",
    field: "username",
    placeholder: { easy: "admin' OR '1'='1' --", medium: "admin' oR '1'='1' --" },
  },
  {
    id: "reflected_xss",
    label: "Reflected XSS",
    field: "query",
    placeholder: { easy: "<script>alert(1)</script>", medium: "<ScRiPt>alert(1)</script>" },
  },
  {
    id: "idor",
    label: "IDOR",
    field: "requested_id",
    numeric: true,
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
        <span />
        <div className="brand">PayloadLab</div>
        <button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          {theme === "dark" ? "☀️ 라이트" : "🌙 다크"}
        </button>
      </header>

      <div className="warning-banner">
        ⚠️ 이 앱은 의도적으로 취약하게 만들어졌습니다. 로컬 Docker 환경에서만 실행하세요.
        외부에 공개하거나, 여기서 배운 기법을 실제 서비스에 시도하지 마세요.
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

          {!selectedCategory && <p className="hint">왼쪽에서 공격 유형을 선택하세요.</p>}

          {selectedCategory && !activeLab && (
            <p className="hint">{activeCategory.label} ({difficulty === "easy" ? "Easy" : "Medium"})는 아직 준비되지 않았습니다.</p>
          )}

          {selectedCategory && activeLab && (
            <div>
              <h2>{activeCategory.label}</h2>
              <form className="attempt-form" onSubmit={submitAttempt}>
                <div className="input-group">
                  <LensInput
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
                    <label className="extra-field-label">{f.label}</label>
                    <input
                      placeholder={f.placeholder}
                      value={extraValues[f.name] ?? ""}
                      onChange={(e) => {
                        setExtraValues((prev) => ({ ...prev, [f.name]: e.target.value }));
                        if (result) setResult(null);
                      }}
                    />
                  </div>
                ))}

                <button type="submit">시도</button>
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
