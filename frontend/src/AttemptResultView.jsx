import FlowStepper from "./FlowStepper.jsx";

export default function AttemptResultView({ result, submittedValue }) {
  return (
    <div>
      <strong className="success-heading">성공! 공격이 통했습니다.</strong>
      <FlowStepper key={submittedValue} steps={result.visualization} />
    </div>
  );
}
