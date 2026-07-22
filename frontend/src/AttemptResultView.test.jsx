import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import AttemptResultView from "./AttemptResultView.jsx";

const xssResult = {
  success: true,
  visualization: [{ step: "input", label: "사용자 입력값", value: "<script>alert(1)</script>", note: null }],
  server_state: null,
  code_snippet: 'return f"<p>...</p>"',
};

const sqliResult = {
  success: true,
  visualization: [{ step: "input", label: "사용자 입력값", value: "admin' OR '1'='1' --", note: null }],
  server_state: { variables: [{ name: "username", value: "admin' OR", highlight: "admin' OR" }], table: null },
  code_snippet: "query = f'...'",
};

describe("AttemptResultView", () => {
  it("Reflected XSS 성공은 서버가 돌려준 페이지를 실제로 실행하는 iframe을 렌더한다", () => {
    const { container } = render(
      <AttemptResultView
        result={xssResult}
        submittedValue="<script>alert(1)</script>"
        labId="reflected-xss-easy"
        category="reflected_xss"
      />,
    );
    const iframe = container.querySelector("iframe.live-frame");
    expect(iframe).toBeInTheDocument();
    expect(iframe.getAttribute("src")).toContain("/labs/reflected-xss-easy/render");
  });

  it("서버 상태가 있는 랩은 세 탭을 보여주고 iframe은 없다", () => {
    const { container } = render(
      <AttemptResultView
        result={sqliResult}
        submittedValue="admin' OR '1'='1' --"
        labId="sql-injection-easy"
        category="sql_injection"
      />,
    );
    expect(screen.getByRole("tab", { name: /서버 상태/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /코드/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /처리 흐름/ })).toBeInTheDocument();
    expect(container.querySelector("iframe")).not.toBeInTheDocument();
  });
});
