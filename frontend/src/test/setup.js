import "@testing-library/jest-dom";

// jsdom은 canvas 2d 컨텍스트를 구현하지 않아 getContext가 에러 로그를 뿜는다.
// LensInput은 ctx가 없으면 글자 수 기반으로 폭을 근사하므로, null을 반환하도록
// 눌러 로그 노이즈만 제거한다 (동작은 그대로).
HTMLCanvasElement.prototype.getContext = () => null;
