from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

from pydantic import BaseModel


Difficulty = Literal["easy", "medium"]


@dataclass
class RuleCheck:
    id: str
    description: str
    check: Callable[[Any], bool]


class VisualizationStep(BaseModel):
    step: str
    label: str
    value: str
    note: Optional[str] = None


class LabMetadata(BaseModel):
    id: str
    name: str
    category: str
    difficulty: Difficulty
    route: str


class AttemptResult(BaseModel):
    success: bool
    visualization: Optional[list[VisualizationStep]] = None
    lens_message: Optional[str] = None
    lens_rule_id: Optional[str] = None
    lens_passed_count: int = 0
    lens_checklist: Optional[list[str]] = None


@dataclass
class Lab:
    """Common lab interface, validated in issues #3/#5/#9.

    A lab supplies its own success/failure oracle via `resolve`; the shared
    `rules` chain is used only to produce the Lens diagnostic when `resolve`
    reports failure (see issue #6: this is where the real fallback lives —
    a rule's `check()` raising on malformed input, not "no rule matched",
    since the chain structurally always returns something).
    """

    metadata: LabMetadata
    rules: list[RuleCheck]
    resolve: Callable[[Any], tuple[bool, Optional[list[VisualizationStep]]]]

    def attempt(self, payload: Any) -> AttemptResult:
        success, visualization = self.resolve(payload)
        if success:
            return AttemptResult(success=True, visualization=visualization)
        return self._diagnose(payload)

    def _diagnose(self, payload: Any) -> AttemptResult:
        for i, rule in enumerate(self.rules):
            try:
                passed = rule.check(payload)
            except Exception:
                return AttemptResult(
                    success=False,
                    lens_message="입력을 인식하지 못했습니다. 이 랩이 기대하는 입력 형태를 확인해보세요.",
                    lens_rule_id="fallback_unrecognized_input",
                    lens_passed_count=i,
                    lens_checklist=self._checklist(i),
                )
            if not passed:
                return AttemptResult(
                    success=False,
                    lens_message=rule.description,
                    lens_rule_id=rule.id,
                    lens_passed_count=i,
                    lens_checklist=self._checklist(i),
                )
        # every rule passed but resolve() still said failure: shouldn't
        # normally happen, but don't crash — surface it plainly.
        return AttemptResult(
            success=False,
            lens_message="모든 조건은 충족했지만 공격이 최종적으로 성립하지 않았습니다.",
            lens_rule_id="fallback_all_rules_passed",
            lens_passed_count=len(self.rules),
            lens_checklist=self._checklist(len(self.rules)),
        )

    def _checklist(self, failed_index: int) -> list[str]:
        checklist = []
        for i, rule in enumerate(self.rules):
            mark = "v" if i < failed_index else ("x" if i == failed_index else "?")
            checklist.append(f"[{mark}] {rule.description}")
        return checklist
