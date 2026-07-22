import re
from typing import Callable, Optional

from app.core.lab import (
    CodeSpan,
    DerivSpan,
    DerivStep,
    ExecutionGraph,
    GraphSegment,
    Lab,
    LabMetadata,
    RuleCheck,
    SuccessDetail,
    VisualizationStep,
)

_SCRIPT_OPEN = re.compile(r"<script", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"</script>", re.IGNORECASE)
_TAG_OPEN = re.compile(r"(?i)<script[^>]*>")
_TAG_CLOSE = re.compile(r"(?i)</script>")

_CODE_SNIPPET_EASY = 'return f"<p>\'{query}\'에 대한 검색 결과입니다</p>"'
_CODE_SNIPPET_MEDIUM = (
    "query = query.replace('<script', '')  # 소문자 <script만 지우는 순진한 필터\n"
    'return f"<p>\'{query}\'에 대한 검색 결과입니다</p>"'
)


def _identity_filter(query: str) -> str:
    return query


def _strip_lowercase_script_open(query: str) -> str:
    """Medium용 순진한 블랙리스트: 정확히 소문자 <script만 지운다 (<ScRiPt>는 못 잡음)."""
    return query.replace("<script", "")


def _render_search_page(query: str) -> str:
    # 검색어를 이스케이프 없이 그대로 HTML에 삽입 (의도적으로 취약)
    return f"<p>'{query}'에 대한 검색 결과입니다</p>"


def _make_render(filter_fn: Callable[[str], str]):
    def render_page(payload: dict) -> str:
        """실제 브라우저에서 새로 파싱되는 완전한 HTML 문서.

        프론트엔드가 이걸 <iframe src="...">로 진짜 내비게이션하면, innerHTML
        주입과 달리 <script> 태그가 실제로 실행됩니다 (DVWA와 같은 방식).
        """
        query = filter_fn(payload.get("query", ""))
        body = _render_search_page(query)
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<style>body{font-family:sans-serif;padding:1rem;background:#fff;color:#111}</style>"
            f"</head><body>{body}</body></html>"
        )

    return render_page


def _has_script_open_raw(payload: dict) -> bool:
    return bool(_SCRIPT_OPEN.search(payload.get("query", "")))

def _has_script_close(payload: dict) -> bool:
    return bool(_SCRIPT_CLOSE.search(payload.get("query", "")))

def _script_open_survives_filter(payload: dict) -> bool:
    filtered = _strip_lowercase_script_open(payload.get("query", ""))
    return bool(_SCRIPT_OPEN.search(filtered))


# --------------------------------------------------------------------------
# ExecutionGraph 빌더 (#19): XSS는 "문자열이 변형된 뒤 서버→브라우저 경계를 넘어
# 코드로 실행되는" 파이프라인. 마지막 단계(live)는 실제 실행 iframe에 연결된다.
# --------------------------------------------------------------------------

_XSS_ROLE_STYLE = {"breakout": "taint", "injected": "taint"}


def _segment_query(q: str) -> list[GraphSegment]:
    mo = _TAG_OPEN.search(q)
    mc = _TAG_CLOSE.search(q)
    if not (mo and mc and mo.end() <= mc.start()):
        return [GraphSegment(id="js", text=q, role="injected")]
    segs: list[GraphSegment] = []
    if q[: mo.start()]:
        segs.append(GraphSegment(id="pre", text=q[: mo.start()], role="benign"))
    segs.append(GraphSegment(id="open", text=q[mo.start() : mo.end()], role="breakout"))
    if q[mo.end() : mc.start()]:
        segs.append(GraphSegment(id="js", text=q[mo.end() : mc.start()], role="injected"))
    segs.append(GraphSegment(id="close", text=q[mc.start() : mc.end()], role="breakout"))
    if q[mc.end() :]:
        segs.append(GraphSegment(id="post", text=q[mc.end() :], role="benign"))
    return segs


def _build_xss_graph(raw_query: str, has_filter: bool) -> ExecutionGraph:
    segs = _segment_query(raw_query)
    script_segs = [s for s in segs if s.id in ("open", "js", "close")]

    steps: list[DerivStep] = [
        DerivStep(
            id="template",
            kind="query",
            side="server",
            label="① 서버가 만드는 응답 HTML 틀",
            spans=[
                DerivSpan(text="<p>'"),
                DerivSpan(text="여기", style="slot"),
                DerivSpan(text="'에 대한 검색 결과입니다</p>"),
            ],
            note="검색어(여기)가 이스케이프 없이 그대로 들어간다",
        ),
        DerivStep(
            id="filled",
            kind="query",
            side="server",
            label="② 입력이 HTML에 글자 그대로 삽입",
            spans=[DerivSpan(text="<p>'")]
            + [DerivSpan(text=s.text, group=s.id, style=_XSS_ROLE_STYLE.get(s.role, "")) for s in segs]
            + [DerivSpan(text="'에 대한 검색 결과입니다</p>")],
            note="입력이 문서의 일부가 되어 버린다",
        ),
    ]

    if has_filter:
        steps.append(
            DerivStep(
                id="filter",
                kind="query",
                side="server",
                label="②′ 순진한 필터를 통과",
                spans=[
                    DerivSpan(text="필터가 소문자 "),
                    DerivSpan(text="<script", style="muted"),
                    DerivSpan(text="만 지움 → 대소문자 섞은 "),
                    DerivSpan(text=next((s.text for s in segs if s.id == "open"), "<ScRiPt>"), group="open", style="taint"),
                    DerivSpan(text="는 살아남음"),
                ],
                note="Medium의 필터는 정확히 소문자 <script만 제거한다",
            )
        )

    steps.append(
        DerivStep(
            id="boundary",
            kind="boundary",
            label="서버 → 브라우저",
            note="여기서부터 브라우저가 이 문자열을 텍스트가 아니라 HTML로 해석한다",
        )
    )
    steps.append(
        DerivStep(
            id="parse",
            kind="query",
            side="browser",
            label="③ 브라우저가 <script>를 태그로 인식",
            spans=[DerivSpan(text=s.text, group=s.id, style="taint") for s in script_segs],
            note="따옴표 안 텍스트가 아니라 '실행할 코드'로 읽는다",
        )
    )
    steps.append(
        DerivStep(
            id="live",
            kind="live",
            side="browser",
            label="④ 실제로 실행된 결과 (진짜 브라우저 실행)",
            note="아래는 우리 서버가 돌려준 페이지를 iframe으로 진짜 로드한 것 — <script>가 실제로 실행된다",
        )
    )
    steps.append(
        DerivStep(
            id="verdict",
            kind="verdict",
            status="success",
            text="브라우저가 스크립트를 실제로 실행 — Reflected XSS 성공",
        )
    )

    code = [
        CodeSpan(text='return f"<p>\''),
        CodeSpan(text="{query}", group="open"),
        CodeSpan(text="'에 대한 검색 결과입니다</p>\""),
    ]
    return ExecutionGraph(
        attack="reflected_xss",
        shape="derivation",
        payload_segments=segs,
        code_caption="취약한 검색 결과 렌더",
        code=code,
        steps=steps,
    )


def _make_resolve(filter_fn: Callable[[str], str], code_snippet: str, route: str, has_filter: bool = False):
    def _resolve(payload: dict) -> tuple[bool, Optional[SuccessDetail]]:
        raw_query = payload.get("query", "")
        filtered_query = filter_fn(raw_query)
        success = bool(_SCRIPT_OPEN.search(filtered_query)) and bool(_SCRIPT_CLOSE.search(filtered_query))
        if not success:
            return False, None

        visualization = [
            VisualizationStep(step="input", label="사용자 입력값", value=raw_query),
            VisualizationStep(
                step="request", label="요청 또는 브라우저 이벤트",
                value=f"GET {route}/render?query={raw_query}",
                note="Reflected XSS는 이렇게 쿼리스트링에 실린 입력이 그대로 페이지에 되비쳐질 때 성립합니다. 위 화면의 실제 실행 결과가 바로 이 URL을 브라우저가 로드한 결과입니다.",
            ),
            VisualizationStep(
                step="processing", label="서버 라우터 또는 브라우저 처리 단계",
                value="서버가 쿼리 파라미터를 그대로 받아 검색 결과 안내 HTML에 삽입",
            ),
            VisualizationStep(
                step="result", label="공격 성공 결과",
                value="페이지 로드 시 브라우저가 스크립트를 실제로 실행함 (위 실행 결과 참고)",
            ),
        ]

        return True, SuccessDetail(
            visualization=visualization,
            code_snippet=code_snippet,
            execution_graph=_build_xss_graph(raw_query, has_filter),
        )

    return _resolve


reflected_xss_easy = Lab(
    metadata=LabMetadata(
        id="reflected-xss-easy",
        name="Reflected XSS (Easy)",
        category="reflected_xss",
        difficulty="easy",
        route="/labs/reflected-xss-easy",
    ),
    rules=[
        RuleCheck("script_open", "<script> 여는 태그가 없습니다.", _has_script_open_raw),
        RuleCheck("script_close", "여는 태그는 있지만 </script> 닫는 태그가 없어 브라우저가 스크립트로 인식하지 못합니다.", _has_script_close),
    ],
    resolve=_make_resolve(_identity_filter, _CODE_SNIPPET_EASY, "/labs/reflected-xss-easy"),
    render=_make_render(_identity_filter),
)

reflected_xss_medium = Lab(
    metadata=LabMetadata(
        id="reflected-xss-medium",
        name="Reflected XSS (Medium)",
        category="reflected_xss",
        difficulty="medium",
        route="/labs/reflected-xss-medium",
    ),
    rules=[
        RuleCheck("script_open", "<script> 여는 태그가 없습니다.", _has_script_open_raw),
        RuleCheck("filter_bypass", "필터가 정확히 소문자 <script만 제거합니다. <ScRiPt>처럼 대소문자를 섞어보세요.", _script_open_survives_filter),
        RuleCheck("script_close", "여는 태그는 있지만 </script> 닫는 태그가 없어 브라우저가 스크립트로 인식하지 못합니다.", _has_script_close),
    ],
    resolve=_make_resolve(_strip_lowercase_script_open, _CODE_SNIPPET_MEDIUM, "/labs/reflected-xss-medium", has_filter=True),
    render=_make_render(_strip_lowercase_script_open),
)
