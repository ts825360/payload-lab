import re
import sqlite3
from typing import Callable, Optional

from app.core.lab import (
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


def _make_resolve(filter_fn: Callable[[str], str], code_snippet: str, route: str):
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
    resolve=_make_resolve(_strip_uppercase_or, _CODE_SNIPPET_MEDIUM, "/labs/sql-injection-medium"),
)
