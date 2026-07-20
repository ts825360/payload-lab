export default function Sidebar({
  categories,
  selectedCategory,
  onSelectCategory,
  difficulty,
  onSelectDifficulty,
  isDifficultyAvailable,
}) {
  return (
    <aside className="sidebar">
      <nav className="lab-nav">
        {categories.map((c) => (
          <button
            key={c.id}
            className={c.id === selectedCategory ? "active" : ""}
            onClick={() => onSelectCategory(c.id)}
          >
            {c.label}
          </button>
        ))}
      </nav>

      <div className="difficulty-selector">
        <div className="difficulty-label">난이도</div>
        <div className="difficulty-buttons">
          {["easy", "medium"].map((d) => (
            <button
              key={d}
              className={d === difficulty ? "active" : ""}
              disabled={!isDifficultyAvailable(d)}
              title={!isDifficultyAvailable(d) ? "아직 구현되지 않았습니다" : undefined}
              onClick={() => onSelectDifficulty(d)}
            >
              {d === "easy" ? "Easy" : "Medium"}
            </button>
          ))}
        </div>
      </div>
    </aside>
  );
}
