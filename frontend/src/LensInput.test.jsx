import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import LensInput from "./LensInput.jsx";

const steps = [
  { status: "failed", description: "따옴표로 문자열을 탈출하지 못했습니다." },
  { status: "unknown", description: "항상 참인 조건이 필요합니다." },
];

describe("LensInput", () => {
  it("빈 입력으로 실패해도 hover 가능한 밑줄이 최소 폭으로 그려진다 (#1 회귀 방지)", () => {
    const { container } = render(
      <LensInput value="" onChange={() => {}} placeholder="p" failed lensMessage="msg" lensSteps={steps} />,
    );
    const mark = container.querySelector(".underline-mark");
    expect(mark).toBeInTheDocument();
    // 폭이 0이면 hover 대상이 사라져 Lens에 도달할 수 없다 -> 최소 폭 보장 확인
    expect(parseFloat(mark.style.width)).toBeGreaterThanOrEqual(28);
  });

  it("입력란에 포커스만 줘도 Lens 진단이 열린다 (키보드·터치 접근성)", () => {
    render(
      <LensInput value="" onChange={() => {}} placeholder="p" failed lensMessage="따옴표 탈출 실패" lensSteps={steps} />,
    );
    expect(screen.queryByText("따옴표 탈출 실패")).not.toBeInTheDocument();
    fireEvent.focus(screen.getByRole("textbox"));
    expect(screen.getByText("따옴표 탈출 실패")).toBeInTheDocument();
  });

  it("실패가 아니면 밑줄을 그리지 않는다", () => {
    const { container } = render(
      <LensInput value="admin" onChange={() => {}} placeholder="p" failed={false} />,
    );
    expect(container.querySelector(".underline-mark")).not.toBeInTheDocument();
  });
});
