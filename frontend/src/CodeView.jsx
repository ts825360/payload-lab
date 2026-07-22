export default function CodeView({ code }) {
  return (
    <figure className="code-window">
      <figcaption className="code-window-bar">
        <span className="code-dot" aria-hidden="true" />
        <span className="code-dot" aria-hidden="true" />
        <span className="code-dot" aria-hidden="true" />
        <span className="code-window-title">취약한 서버 코드</span>
      </figcaption>
      <pre className="code-view">
        <code>{code}</code>
      </pre>
    </figure>
  );
}
