function highlightText(value, needle) {
  if (!needle) return value;
  const idx = value.indexOf(needle);
  if (idx === -1) return value;
  return (
    <>
      {value.slice(0, idx)}
      <mark className="payload-highlight">{needle}</mark>
      {value.slice(idx + needle.length)}
    </>
  );
}

export default function ServerStateView({ state }) {
  return (
    <div className="state-diagram">
      <div className="state-block">
        <div className="state-col-title">변수</div>
        {state.variables.map((v) => (
          <div className="state-var-row" key={v.name}>
            <span className="state-var-name">{v.name}</span>
            <span className="state-arrow">→</span>
            <span className="state-var-value">{highlightText(v.value, v.highlight)}</span>
          </div>
        ))}
      </div>

      {state.table && (
        <div className="state-block">
          <div className="state-col-title">{state.table.name} 테이블</div>
          <table className="state-table">
            <thead>
              <tr>
                {state.table.columns.map((c) => (
                  <th key={c}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {state.table.rows.map((row, i) => (
                <tr key={i} className={state.table.matched_row_indices.includes(i) ? "matched" : ""}>
                  {row.map((cell, j) => (
                    <td key={j}>{cell}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          <div className="state-hint">→ 강조된 줄 = 이 payload로 실제 매칭된 행</div>
        </div>
      )}
    </div>
  );
}
