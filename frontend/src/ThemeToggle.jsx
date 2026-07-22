// 해 ↔ 초승달로 부드럽게 모핑되는 테마 토글.
// 라이트: 광선이 펼쳐진 태양(앰버) / 다크: 광선이 오므라들고 원반이 초승달로
// 깎인 달(보라). 깎임은 mask 안의 검은 원을 원반 위로 슬라이드해서 만든다.
export default function ThemeToggle({ theme, onToggle }) {
  const isDark = theme === "dark";
  const label = isDark ? "라이트 모드로 전환" : "다크 모드로 전환";
  return (
    <button
      className={"theme-toggle" + (isDark ? " is-dark" : "")}
      onClick={onToggle}
      aria-label={label}
      title={label}
    >
      <svg className="theme-icon" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
        <mask id="theme-moon-mask">
          <rect x="0" y="0" width="24" height="24" fill="#fff" />
          <circle className="moon-cutout" cx="18" cy="6" r="6" fill="#000" />
        </mask>
        <circle className="sun-disc" cx="12" cy="12" r="6" fill="currentColor" mask="url(#theme-moon-mask)" />
        <g className="sun-rays" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <line x1="12" y1="1" x2="12" y2="3" />
          <line x1="12" y1="21" x2="12" y2="23" />
          <line x1="1" y1="12" x2="3" y2="12" />
          <line x1="21" y1="12" x2="23" y2="12" />
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
        </g>
      </svg>
    </button>
  );
}
