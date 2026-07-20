import re
from typing import Optional

from app.core.lab import Lab, LabMetadata, RuleCheck, SuccessDetail, VisualizationStep

_SCRIPT_OPEN = re.compile(r"<script", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"</script>", re.IGNORECASE)

_CODE_SNIPPET = 'return f"<p>\'{query}\'에 대한 검색 결과입니다</p>"'


def _render_search_page(query: str) -> str:
    # 검색어를 이스케이프 없이 그대로 HTML에 삽입 (의도적으로 취약)
    return f"<p>'{query}'에 대한 검색 결과입니다</p>"


def render_page(payload: dict) -> str:
    """실제 브라우저에서 새로 파싱되는 완전한 HTML 문서.

    프론트엔드가 이걸 <iframe src="...">로 진짜 내비게이션하면, innerHTML
    주입과 달리 <script> 태그가 실제로 실행됩니다 (DVWA와 같은 방식).
    """
    query = payload.get("query", "")
    body = _render_search_page(query)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<style>body{font-family:sans-serif;padding:1rem;background:#fff;color:#111}</style>"
        f"</head><body>{body}</body></html>"
    )


def _has_script_open(payload: dict) -> bool:
    return bool(_SCRIPT_OPEN.search(payload.get("query", "")))

def _has_script_close(payload: dict) -> bool:
    return bool(_SCRIPT_CLOSE.search(payload.get("query", "")))


def _resolve(payload: dict) -> tuple[bool, Optional[SuccessDetail]]:
    query = payload.get("query", "")
    success = _has_script_open(payload) and _has_script_close(payload)
    if not success:
        return False, None

    visualization = [
        VisualizationStep(step="input", label="사용자 입력값", value=query),
        VisualizationStep(
            step="request", label="요청 또는 브라우저 이벤트",
            value=f"GET /labs/reflected-xss-easy/attempt?query={query}",
        ),
        VisualizationStep(
            step="processing", label="서버 라우터 또는 브라우저 처리 단계",
            value="서버가 쿼리 파라미터를 그대로 받아 검색 결과 안내 HTML에 삽입",
        ),
        VisualizationStep(
            step="result", label="공격 성공 결과",
            value="페이지 로드 시 브라우저가 스크립트를 실제로 실행함 (아래 실행 결과 탭 참고)",
        ),
    ]

    return True, SuccessDetail(visualization=visualization, code_snippet=_CODE_SNIPPET)


reflected_xss_easy = Lab(
    metadata=LabMetadata(
        id="reflected-xss-easy",
        name="Reflected XSS (Easy)",
        category="reflected_xss",
        difficulty="easy",
        route="/labs/reflected-xss-easy",
    ),
    rules=[
        RuleCheck("script_open", "<script> 여는 태그가 없습니다.", _has_script_open),
        RuleCheck("script_close", "여는 태그는 있지만 </script> 닫는 태그가 없어 브라우저가 스크립트로 인식하지 못합니다.", _has_script_close),
    ],
    resolve=_resolve,
    render=render_page,
)
