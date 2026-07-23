import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import AttemptResultView from "./AttemptResultView.jsx";

const sqliResult = {
  success: true,
  execution_graph: {
    attack: "sql_injection",
    shape: "derivation",
    payload_segments: [{ id: "or", text: " OR '1'='1'", role: "logic" }],
    code: [],
    code_caption: "",
    steps: [{ id: "verdict", kind: "verdict", status: "success", text: "로그인 성공" }],
  },
};

const xssResult = {
  success: true,
  execution_graph: {
    attack: "reflected_xss",
    shape: "derivation",
    payload_segments: [{ id: "open", text: "<script>", role: "breakout" }],
    code: [],
    code_caption: "",
    steps: [
      { id: "live", kind: "live", label: "실행", note: "" },
      { id: "verdict", kind: "verdict", status: "success", text: "XSS 성공" },
    ],
  },
};

describe("AttemptResultView", () => {
  it("성공 배너와 실행 다이어그램을 함께 렌더한다", () => {
    render(<AttemptResultView result={sqliResult} submittedValue="admin' OR '1'='1' --" labId="sql-injection-easy" />);
    expect(screen.getByText("공격 성공")).toBeInTheDocument();
    expect(screen.getByText("로그인 성공")).toBeInTheDocument();
  });

  it("XSS의 live 단계로 labId·submittedValue를 넘겨 실제 실행 iframe을 띄운다", () => {
    const { container } = render(
      <AttemptResultView result={xssResult} submittedValue="<script>alert(1)</script>" labId="reflected-xss-easy" />,
    );
    const iframe = container.querySelector("iframe.deriv-live-frame");
    expect(iframe).toBeInTheDocument();
    expect(iframe.getAttribute("src")).toContain("/labs/reflected-xss-easy/render");
  });
});
