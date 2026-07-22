import re
import sqlite3
from typing import Callable, Optional

from app.core.lab import (
    CodeSpan,
    Condition,
    DerivSpan,
    DerivStep,
    ExecutionGraph,
    GraphSegment,
    GraphTableRow,
    Lab,
    LabMetadata,
    RuleCheck,
    ServerState,
    SuccessDetail,
    TableState,
    VariableState,
    VisualizationStep,
)

# 실제 취약한 로그인 조회를 흉내내기 위해, 매 시도마다 :memory: SQLite DB를
# 새로 만들고 시드 데이터를 넣습니다. 진짜 쿼리 실행 결과로 성공/실패를
# 판정합니다 (스파이크 단계의 문자열 패턴 매칭과 달리, 실제 DB 엔진을 씀).

_SEED_USERS = [
    (1, "admin", "s3cr3t_password"),
    (2, "guest", "guest123"),
]


def _seed_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.executemany("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", _SEED_USERS)
    conn.commit()
    return conn


def _identity_filter(username: str) -> str:
    return username


def _strip_uppercase_or(username: str) -> str:
    """Medium용 순진한 블랙리스트: 정확히 대문자 OR만 지운다 (Or, oR은 못 잡음)."""
    return username.replace("OR", "")


def _run_login_query(username: str, filter_fn: Callable[[str], str]) -> tuple[bool, str, list[tuple]]:
    """공격자는 비밀번호를 모른다고 가정 -- 항상 틀린 비밀번호로 시도."""
    filtered = filter_fn(username)
    conn = _seed_db()
    query = (
        f"SELECT * FROM users WHERE username = '{filtered}' "
        "AND password = 'this_is_definitely_wrong'"
    )
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return bool(rows), query, rows


_CODE_SNIPPET_EASY = (
    "query = f\"SELECT * FROM users WHERE username = '{username}' \"\n"
    "        \"AND password = '{password}'\"\n"
    "rows = conn.execute(query).fetchall()"
)

_CODE_SNIPPET_MEDIUM = (
    "username = username.replace('OR', '')  # 대문자 OR만 지우는 순진한 필터\n"
    "query = f\"SELECT * FROM users WHERE username = '{username}' \"\n"
    "        \"AND password = '{password}'\"\n"
    "rows = conn.execute(query).fetchall()"
)


# --------------------------------------------------------------------------
# ExecutionGraph 빌더 (#19): 성공한 SQLi 시도를 "쿼리가 단계별로 변형되는
# 유도 과정"으로 서술한다. 반환된 행·주석 유무·필터 우회 등 실제 상황을 반영.
# --------------------------------------------------------------------------

_ROLE_STYLE = {"benign": "", "breakout": "taint", "logic": "taint", "comment": "comment"}


def _segment_username(u: str) -> list[GraphSegment]:
    """페이로드를 benign/breakout(')/logic/comment(--) 조각으로 쪼갠다.

    전체 SQL 파서가 아니라, 첫 따옴표와 주석 마커 기준의 휴리스틱 분할 -- MVP의
    표준 성공 페이로드와 그 변형(대소문자 등)을 정확히 커버한다.
    """
    qi = u.find("'")
    if qi == -1:
        return [GraphSegment(id="user", text=u, role="benign")]
    benign, rest = u[:qi], u[qi + 1 :]
    ci = -1
    for marker in ("--", "#"):
        idx = rest.find(marker)
        if idx != -1:
            ci = idx
            break
    segs: list[GraphSegment] = []
    if benign:
        segs.append(GraphSegment(id="user", text=benign, role="benign"))
    segs.append(GraphSegment(id="quote", text="'", role="breakout"))
    if ci != -1:
        if rest[:ci]:
            segs.append(GraphSegment(id="logic", text=rest[:ci], role="logic"))
        segs.append(GraphSegment(id="comment", text=rest[ci:], role="comment"))
    elif rest:
        segs.append(GraphSegment(id="logic", text=rest, role="logic"))
    return segs


def _seg_text(segs: list[GraphSegment], sid: str) -> str:
    return next((s.text for s in segs if s.id == sid), "")


def _build_sqli_graph(
    raw_username: str, rows: list[tuple], has_filter: bool
) -> ExecutionGraph:
    segs = _segment_username(raw_username)
    has_comment = any(s.id == "comment" for s in segs)
    has_logic = any(s.id == "logic" for s in segs)
    benign = _seg_text(segs, "user")
    logic_text = _seg_text(segs, "logic")

    steps: list[DerivStep] = [
        DerivStep(
            id="template",
            kind="query",
            label="① 서버가 만드는 질문 틀",
            spans=[
                DerivSpan(text="SELECT * FROM users WHERE username = '"),
                DerivSpan(text="여기", style="slot"),
                DerivSpan(text="' AND password = '"),
                DerivSpan(text="여기", style="slot"),
                DerivSpan(text="'"),
            ],
            note="빈칸(여기)에 입력이 그대로 들어간다",
        ),
        DerivStep(
            id="filled",
            kind="query",
            label="② 입력이 이름칸에 글자 그대로",
            spans=[DerivSpan(text="… WHERE username = '")]
            + [DerivSpan(text=s.text, group=s.id, style=_ROLE_STYLE.get(s.role, "taint")) for s in segs]
            + [DerivSpan(text="' AND password = '…'")],
            note="입력이 쿼리의 일부가 되어 버린다",
        ),
    ]

    if has_filter:
        steps.append(
            DerivStep(
                id="filter",
                kind="query",
                label="②′ 순진한 필터를 통과",
                spans=[
                    DerivSpan(text="필터가 대문자 "),
                    DerivSpan(text="OR", style="muted"),
                    DerivSpan(text="만 지움 → 대소문자 섞은 "),
                    DerivSpan(text=logic_text or "oR …", group="logic", style="taint"),
                    DerivSpan(text=" 은 살아남음"),
                ],
                note="Medium의 필터는 정확히 대문자 OR만 제거한다",
            )
        )

    if has_comment:
        steps.append(
            DerivStep(
                id="comment",
                kind="query",
                label="③ 뒷부분이 주석으로 꺼짐",
                spans=[
                    DerivSpan(text=f"… username = '{benign}'"),
                    DerivSpan(text=logic_text, group="logic", style="taint"),
                    DerivSpan(text=" "),
                    DerivSpan(
                        text=_seg_text(segs, "comment") + " ' AND password = '…'",
                        group="comment",
                        style="comment",
                    ),
                ],
                note="-- 뒤(비밀번호 검사)는 주석 → 컴퓨터가 무시한다",
            )
        )

    if has_logic:
        steps.append(
            DerivStep(
                id="split",
                kind="split",
                op="OR",
                label="④ 조건이 둘로 쪼개짐",
                conditions=[
                    Condition(text=f"username = '{benign}' 인가?", result="확인 필요"),
                    Condition(text="'1'='1' 인가?", group="logic", result="언제나 참"),
                ],
                note="OR: 둘 중 하나만 참이면 조건 전체가 참",
            )
        )

    matched = [i for i, u in enumerate(_SEED_USERS) if u in rows]
    steps.append(
        DerivStep(
            id="table",
            kind="table",
            label="⑤ 조건이 참이라 걸러진 행",
            columns=["id", "username", "password"],
            rows=[
                GraphTableRow(cells=[str(u[0]), u[1], u[2]], matched=(i in matched))
                for i, u in enumerate(_SEED_USERS)
            ],
            note="비밀번호를 몰라도 조건이 참이라 행이 반환된다",
        )
    )
    steps.append(
        DerivStep(
            id="verdict",
            kind="verdict",
            status="success",
            text=f"로그인 성공 — {len(rows)}개 행 반환, 비밀번호 없이 통과",
        )
    )

    code = [
        CodeSpan(text='query = f"… WHERE username = \''),
        CodeSpan(text="{username}", group="quote"),
        CodeSpan(text="' AND "),
        CodeSpan(text="password = '…'", group="comment"),
        CodeSpan(text='"'),
    ]
    return ExecutionGraph(
        attack="sql_injection",
        shape="derivation",
        payload_segments=segs,
        code_caption="취약한 로그인 쿼리",
        code=code,
        steps=steps,
    )


def _make_resolve(filter_fn: Callable[[str], str], code_snippet: str, route: str, has_filter: bool = False):
    def _resolve(payload: dict) -> tuple[bool, Optional[SuccessDetail]]:
        username = payload.get("username", "")
        success, query, rows = _run_login_query(username, filter_fn)
        if not success:
            return False, None

        visualization = [
            VisualizationStep(step="input", label="사용자 입력값", value=username),
            VisualizationStep(
                step="request", label="요청 또는 브라우저 이벤트",
                value=f'POST {route}/attempt  body: {{"username": "{username}"}}',
            ),
            VisualizationStep(
                step="processing", label="서버 라우터 또는 브라우저 처리 단계",
                value="로그인 라우터가 username을 그대로 받아 인증용 SQL 쿼리 문자열을 조립",
            ),
            VisualizationStep(
                step="result", label="공격 성공 결과",
                value=f"비밀번호 몰라도 로그인 성공, 반환된 행: {rows}",
            ),
        ]

        matched_indices = [i for i, u in enumerate(_SEED_USERS) if u in rows]
        server_state = ServerState(
            variables=[
                VariableState(name="username", value=username, highlight=username),
                VariableState(name="query", value=query, highlight=filter_fn(username)),
            ],
            table=TableState(
                name="users",
                columns=["id", "username", "password"],
                rows=[[str(u[0]), u[1], u[2]] for u in _SEED_USERS],
                matched_row_indices=matched_indices,
            ),
        )

        return True, SuccessDetail(
            visualization=visualization,
            server_state=server_state,
            code_snippet=code_snippet,
            execution_graph=_build_sqli_graph(username, rows, has_filter),
        )

    return _resolve


def _has_quote_escape(payload: dict) -> bool:
    return "'" in payload.get("username", "")

def _has_always_true_condition(payload: dict) -> bool:
    username = payload.get("username", "")
    lowered = username.lower()
    return "or" in lowered and ("1'='1" in username or "1=1" in username)

def _has_comment_terminator(payload: dict) -> bool:
    username = payload.get("username", "")
    return "--" in username or "#" in username

def _or_survives_filter(payload: dict) -> bool:
    """필터가 정확한 대문자 OR만 지우므로, 대소문자를 섞으면 살아남는지 확인."""
    filtered = _strip_uppercase_or(payload.get("username", ""))
    return re.search(r"(?i)or", filtered) is not None


sql_injection_easy = Lab(
    metadata=LabMetadata(
        id="sql-injection-easy",
        name="SQL Injection (Easy)",
        category="sql_injection",
        difficulty="easy",
        route="/labs/sql-injection-easy",
    ),
    rules=[
        RuleCheck("quote_escape", "따옴표로 문자열을 탈출하지 못했습니다.", _has_quote_escape),
        RuleCheck("always_true", "따옴표 탈출은 됐지만 항상 참인 조건을 만들지 못했습니다.", _has_always_true_condition),
        RuleCheck("comment_terminator", "조건까지는 맞췄지만 비밀번호 검사를 무력화할 주석이 없습니다.", _has_comment_terminator),
    ],
    resolve=_make_resolve(_identity_filter, _CODE_SNIPPET_EASY, "/labs/sql-injection-easy"),
)

sql_injection_medium = Lab(
    metadata=LabMetadata(
        id="sql-injection-medium",
        name="SQL Injection (Medium)",
        category="sql_injection",
        difficulty="medium",
        route="/labs/sql-injection-medium",
    ),
    rules=[
        RuleCheck("quote_escape", "따옴표로 문자열을 탈출하지 못했습니다.", _has_quote_escape),
        RuleCheck("filter_bypass", "필터가 정확히 대문자 OR만 제거합니다. Or, oR처럼 대소문자를 섞어보세요.", _or_survives_filter),
        RuleCheck("always_true", "따옴표 탈출은 됐지만 항상 참인 조건을 만들지 못했습니다.", _has_always_true_condition),
        RuleCheck("comment_terminator", "조건까지는 맞췄지만 비밀번호 검사를 무력화할 주석이 없습니다.", _has_comment_terminator),
    ],
    resolve=_make_resolve(_strip_uppercase_or, _CODE_SNIPPET_MEDIUM, "/labs/sql-injection-medium", has_filter=True),
)
