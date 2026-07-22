import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import ExecutionGraphView from "./ExecutionGraphView.jsx";

const graph = {
  attack: "sql_injection",
  shape: "derivation",
  payload_segments: [
    { id: "quote", text: "'", role: "breakout" },
    { id: "or", text: " OR '1'='1'", role: "logic" },
  ],
  code_caption: "취약한 쿼리",
  code: [
    { text: "query = '", group: "" },
    { text: "{username}", group: "quote" },
    { text: "'", group: "" },
  ],
  steps: [
    {
      id: "filled",
      kind: "query",
      label: "입력 꽂힘",
      spans: [
        { text: "WHERE username = 'admin", group: "", style: "" },
        { text: " OR '1'='1'", group: "or", style: "taint" },
      ],
      note: "",
    },
    {
      id: "table",
      kind: "table",
      label: "결과",
      columns: ["id", "username"],
      rows: [
        { cells: ["1", "admin"], matched: true },
        { cells: ["2", "guest"], matched: false },
      ],
      note: "",
    },
    { id: "verdict", kind: "verdict", status: "success", text: "로그인 성공" },
  ],
};

describe("ExecutionGraphView", () => {
  it("유도 과정의 단계·결과를 렌더한다", () => {
    const { container } = render(<ExecutionGraphView graph={graph} />);
    expect(screen.getByText("로그인 성공")).toBeInTheDocument();
    // 매칭된 행만 강조
    expect(container.querySelectorAll("tr.matched")).toHaveLength(1);
  });

  it("같은 group을 hover/focus하면 payload·코드·단계가 함께 켜진다 (양방향, 핵심 차별점)", () => {
    const { container } = render(<ExecutionGraphView graph={graph} />);
    // group "or"를 가진 요소: 페이로드 조각 + 쿼리 span (총 2개)
    const orEls = container.querySelectorAll('[data-group="or"]');
    expect(orEls.length).toBeGreaterThanOrEqual(2);
    orEls.forEach((el) => expect(el.className).not.toContain("hl"));
    fireEvent.focus(orEls[0]);
    // 하나를 포커스하면 같은 group 전체가 hl
    container.querySelectorAll('[data-group="or"]').forEach((el) => {
      expect(el.className).toContain("hl");
    });
    // 다른 group("quote")은 켜지지 않음
    container.querySelectorAll('[data-group="quote"]').forEach((el) => {
      expect(el.className).not.toContain("hl");
    });
  });

  it("XSS live 단계는 실제 실행 iframe을 렌더한다", () => {
    const xssGraph = {
      attack: "reflected_xss",
      shape: "derivation",
      payload_segments: [{ id: "open", text: "<script>", role: "breakout" }],
      code: [],
      code_caption: "",
      steps: [
        { id: "boundary", kind: "boundary", label: "서버 → 브라우저", note: "경계" },
        { id: "live", kind: "live", label: "실행", note: "진짜 실행" },
        { id: "verdict", kind: "verdict", status: "success", text: "XSS 성공" },
      ],
    };
    const { container } = render(
      <ExecutionGraphView graph={xssGraph} labId="reflected-xss-easy" submittedValue="<script>alert(1)</script>" />,
    );
    const iframe = container.querySelector("iframe.deriv-live-frame");
    expect(iframe).toBeInTheDocument();
    expect(iframe.getAttribute("src")).toContain("/labs/reflected-xss-easy/render");
  });

  it("IDOR 관계 단계는 내 것/남의 것 owner 화살표를 색으로 구분해 렌더한다", () => {
    const idorGraph = {
      attack: "idor",
      shape: "relational",
      payload_segments: [{ id: "reqid", text: "1043", role: "injected" }],
      code: [],
      code_caption: "",
      steps: [
        { id: "missing", kind: "note", style: "missing", label: "검사 없음", note: "소유권 미확인" },
        {
          id: "relations",
          kind: "relations",
          label: "주인",
          note: "화살표 대비",
          objects: [
            { id: "order_req", title: "주문 1043", subtitle: "주인 = 2001", tone: "other" },
            { id: "owner_other", title: "사용자 2001", subtitle: "남", tone: "other" },
            { id: "order_mine", title: "주문 1042", subtitle: "주인 = 1042", tone: "mine" },
            { id: "me", title: "나", subtitle: "user 1042", tone: "mine" },
          ],
          arrows: [
            { source: "order_req", target: "owner_other", label: "주인", tone: "other" },
            { source: "order_mine", target: "me", label: "주인", tone: "mine" },
          ],
        },
        { id: "verdict", kind: "verdict", status: "success", text: "IDOR 성공" },
      ],
    };
    const { container } = render(<ExecutionGraphView graph={idorGraph} />);
    expect(screen.getByText("IDOR 성공")).toBeInTheDocument();
    expect(container.querySelectorAll(".rel-box.tone-other").length).toBeGreaterThanOrEqual(2);
    expect(container.querySelectorAll(".rel-box.tone-mine").length).toBeGreaterThanOrEqual(2);
    // 소유권 검사 없음(missing) 박스가 점선 강조로 존재
    expect(container.querySelector(".deriv-note-box.missing")).toBeInTheDocument();
  });
});
