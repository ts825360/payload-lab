import { useEffect, useState } from "react";
import { fetchLabs, attemptLab } from "./api.js";
import AttemptResultView from "./AttemptResultView.jsx";
import Sidebar from "./Sidebar.jsx";

export const CATEGORIES = [
  { id: "sql_injection", label: "SQL Injection", field: "username", placeholder: "admin' OR '1'='1' --" },
  { id: "reflected_xss", label: "Reflected XSS", field: "query", placeholder: "<script>alert(1)</script>" },
  { id: "idor", label: "IDOR", field: "requested_id", placeholder: "1043", numeric: true },
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
  const [result, setResult] = useState(null);
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
    setResult(null);
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

  async function submitAttempt(e) {
    e.preventDefault();
    const value = activeCategory.numeric ? Number(inputValue) : inputValue;
    try {
      const res = await attemptLab(activeLab.id, { [activeCategory.field]: value });
      setResult(res);
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
              <h2>{activeLab.name}</h2>
              <form className="attempt-form" onSubmit={submitAttempt}>
                <input
                  placeholder={activeCategory.placeholder}
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                />
                <button type="submit">시도</button>
              </form>
              {result && <AttemptResultView result={result} />}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
