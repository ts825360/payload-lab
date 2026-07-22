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
      <div className="sidebar-section">
        <div className="sidebar-heading">공격 유형</div>
        <nav className="lab-nav">
          {categories.map((c) => (
            <button
              key={c.id}
              className={"lab-nav-item" + (c.id === selectedCategory ? " active" : "")}
              onClick={() => onSelectCategory(c.id)}
            >
              <span className="lab-nav-label">{c.label}</span>
              <span className="lab-nav-tag">{c.tag}</span>
            </button>
          ))}
        </nav>
      </div>

      <div className="sidebar-section difficulty-selector">
        <div className="sidebar-heading">난이도</div>
        <div className="segmented">
          {["easy", "medium"].map((d) => (
            <button
              key={d}
              className={"segmented-btn" + (d === difficulty ? " active" : "")}
              disabled={!isDifficultyAvailable(d)}
              onClick={() => onSelectDifficulty(d)}
            >
              {d === "easy" ? "Easy" : "Medium"}
            </button>
          ))}
        </div>
        {!isDifficultyAvailable("medium") && (
          <p className="difficulty-note">Medium은 아직 준비되지 않았습니다</p>
        )}
      </div>
    </aside>
  );
}
