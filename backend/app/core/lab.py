from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional

from pydantic import BaseModel


Difficulty = Literal["easy", "medium"]


@dataclass
class RuleCheck:
    id: str
    description: str
    check: Callable[[Any], bool]


class LabMetadata(BaseModel):
    id: str
    name: str
    category: str
    difficulty: Difficulty
    route: str


class LensStep(BaseModel):
    status: Literal["passed", "failed", "unknown"]
    description: str


# --------------------------------------------------------------------------
# ExecutionGraph (#19): 성공 시, "서버상태/코드/처리흐름" 3탭을 대체하는 단일
# 관계 그래프. 매 시도의 실제 값으로 채워진다(오라클은 그대로, 그래프는 서술).
#
# 상호 하이라이트는 "공유 group id" 한 가지로 구현한다: payload 조각이 group을
# 정의하고(id == group), 다이어그램의 span/행/코드 조각이 같은 group을 달면,
# 어느 쪽에 hover/focus해도 같은 group 전체가 켜진다(양방향이 구조적으로 보장).
#
# shape="derivation": 문자열이 단계별로 변형되는 유도 과정(SQLi/XSS/CmdInj/Path).
# shape="relational": 객체가 화살표로 연결되는 관계 스냅샷(IDOR). -- 이후 확장.
# --------------------------------------------------------------------------


class GraphSegment(BaseModel):
    """페이로드를 의미 단위로 쪼갠 조각. id가 곧 하이라이트 group."""

    id: str
    text: str
    role: str = ""  # breakout|logic|comment|injected|benign


class DerivSpan(BaseModel):
    """유도 과정의 한 문자열 단계를 이루는 span. group으로 payload/코드와 연결."""

    text: str
    group: str = ""
    style: str = ""  # taint|danger|comment|muted|slot


class Condition(BaseModel):
    text: str
    group: str = ""
    result: str = ""  # 참|거짓|확인 필요


class GraphTableRow(BaseModel):
    cells: list[str]
    matched: bool = False


class CodeSpan(BaseModel):
    text: str
    group: str = ""


class RelObject(BaseModel):
    """관계 그래프(IDOR)의 객체 노드. tone으로 내 것/남의 것/없음을 색으로 구분."""

    id: str
    title: str
    subtitle: str = ""
    tone: str = ""  # mine|other|missing|neutral


class RelArrow(BaseModel):
    """객체 사이의 관계 화살표(예: 주문 → 주인)."""

    source: str
    target: str
    label: str = ""
    tone: str = ""  # mine|other


class DerivStep(BaseModel):
    id: str
    # derivation: query|split|table|verdict|boundary|live|note
    # relational: note|relations|verdict
    kind: str
    label: str = ""
    note: str = ""
    style: str = ""  # note용: "missing" 이면 점선 유령 박스
    side: str = ""  # server|browser (경계 레이아웃 힌트)
    spans: list[DerivSpan] = []  # kind=query
    conditions: list[Condition] = []  # kind=split
    op: str = ""  # kind=split (예: "OR")
    columns: list[str] = []  # kind=table
    rows: list[GraphTableRow] = []  # kind=table
    objects: list[RelObject] = []  # kind=relations
    arrows: list[RelArrow] = []  # kind=relations
    status: str = ""  # kind=verdict: success|blocked
    text: str = ""  # kind=verdict 문구


class ExecutionGraph(BaseModel):
    attack: str
    shape: str = "derivation"
    payload_segments: list[GraphSegment] = []
    code_caption: str = ""
    code: list[CodeSpan] = []
    steps: list[DerivStep] = []


def filter_step(
    *,
    removed: str,
    survivor_text: str,
    survivor_group: str,
    note: str,
    removed_prefix: str = "",
    survivor_prefix: str = "대소문자 섞은 ",
    tail: str = "는 살아남음",
) -> DerivStep:
    """Medium 랩 공통의 "②′ 순진한 필터를 통과" 단계.

    세 랩(SQLi/XSS/CmdInjection)의 필터 우회 설명이 "필터가 {removed}만 지움 →
    {survivor}는 살아남음" 골격으로 동일해서 하나로 추출한다 (code-review 표준
    감사에서 지적된 중복 제거).
    """
    return DerivStep(
        id="filter",
        kind="query",
        label="②′ 순진한 필터를 통과",
        spans=[
            DerivSpan(text=f"필터가 {removed_prefix}"),
            DerivSpan(text=removed, style="muted"),
            DerivSpan(text=f"만 지움 → {survivor_prefix}"),
            DerivSpan(text=survivor_text, group=survivor_group, style="taint"),
            DerivSpan(text=tail),
        ],
        note=note,
    )


class SuccessDetail(BaseModel):
    execution_graph: ExecutionGraph


class AttemptResult(BaseModel):
    success: bool
    execution_graph: Optional[ExecutionGraph] = None
    lens_message: Optional[str] = None
    lens_rule_id: Optional[str] = None
    lens_passed_count: int = 0
    lens_steps: Optional[list[LensStep]] = None


@dataclass
class Lab:
    """Common lab interface, validated in issues #3/#5/#9.

    A lab supplies its own success/failure oracle via `resolve`; the shared
    `rules` chain is used only to produce the Lens diagnostic when `resolve`
    reports failure (see issue #6: this is where the real fallback lives —
    a rule's `check()` raising on malformed input, not "no rule matched",
    since the chain structurally always returns something).

    `render` is optional: labs that can demonstrate a real browser-executed
    exploit (e.g. reflected XSS) provide a function that returns a full raw
    HTML document for a given payload, served through GET /labs/{id}/render
    and loaded in a sandboxed iframe by the frontend — a real navigation, so
    <script> tags in it actually execute, unlike injecting into React's DOM.
    """

    metadata: LabMetadata
    rules: list[RuleCheck]
    resolve: Callable[[Any], tuple[bool, Optional[SuccessDetail]]]
    render: Optional[Callable[[Any], str]] = None

    def attempt(self, payload: Any) -> AttemptResult:
        try:
            success, detail = self.resolve(payload)
        except Exception:
            # resolve() itself choked on the input (e.g. wrong type for a
            # field) -- treat it the same as "resolve said no" and let
            # _diagnose's per-rule exception handling take it from here,
            # instead of a 500. This is the same #6 guarantee `_diagnose`
            # already gives for individual rule checks, extended to cover
            # resolve() too (found via #10's regression suite: resolve()
            # was the one path that could still crash the request).
            return self._diagnose(payload)
        if success:
            return AttemptResult(success=True, execution_graph=detail.execution_graph)
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
                    lens_steps=self._lens_steps(i),
                )
            if not passed:
                return AttemptResult(
                    success=False,
                    lens_message=rule.description,
                    lens_rule_id=rule.id,
                    lens_passed_count=i,
                    lens_steps=self._lens_steps(i),
                )
        # every rule passed but resolve() still said failure: shouldn't
        # normally happen, but don't crash — surface it plainly.
        return AttemptResult(
            success=False,
            lens_message="모든 조건은 충족했지만 공격이 최종적으로 성립하지 않았습니다.",
            lens_rule_id="fallback_all_rules_passed",
            lens_passed_count=len(self.rules),
            lens_steps=self._lens_steps(len(self.rules)),
        )

    def _lens_steps(self, failed_index: int) -> list[LensStep]:
        steps = []
        for i, rule in enumerate(self.rules):
            if i < failed_index:
                status = "passed"
            elif i == failed_index:
                status = "failed"
            else:
                status = "unknown"
            steps.append(LensStep(status=status, description=rule.description))
        return steps
