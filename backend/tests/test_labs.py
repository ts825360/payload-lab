"""#10 Lens 회귀 테스트 스위트.

각 랩의 known payload -> 기대 결과(성공/실패 및 어느 규칙에서 멈추는지)를
고정해둔다. 팀원이 #14~#16 작업으로 backend/app/labs/*.py 안의 description/
note 문자열을 고치다가 실수로 로직(정규식, 필터 등)까지 건드리면 여기서
바로 잡힌다.
"""

from app.labs import REGISTRY, sql_injection, reflected_xss, idor, command_injection


def test_all_mvp_labs_registered():
    expected_ids = {
        "sql-injection-easy", "sql-injection-medium",
        "reflected-xss-easy", "reflected-xss-medium",
        "idor-easy", "idor-medium",
    }
    assert expected_ids <= REGISTRY.keys()


# ---------------------------------------------------------------- SQL Injection

def test_sqli_easy_success():
    result = sql_injection.sql_injection_easy.attempt({"username": "admin' OR '1'='1' --"})
    assert result.success is True
    assert result.server_state is not None
    assert result.server_state.table.matched_row_indices  # 최소 한 행은 매칭됨


def test_sqli_easy_fails_at_quote_escape():
    result = sql_injection.sql_injection_easy.attempt({"username": "admin"})
    assert result.success is False
    assert result.lens_rule_id == "quote_escape"
    assert result.lens_passed_count == 0


def test_sqli_easy_fails_at_always_true():
    result = sql_injection.sql_injection_easy.attempt({"username": "admin'"})
    assert result.success is False
    assert result.lens_rule_id == "always_true"
    assert result.lens_passed_count == 1


def test_sqli_easy_fails_at_comment_terminator():
    # 'admin' 자체가 실존 유저라 "admin' OR ..."는 주석 없이도 성공해버린다
    # (OR 왼쪽만으로 매칭됨 -- 실제 실행 오라클의 정확성을 보여준 사례,
    # #9 스파이크에서도 같은 걸 확인함). 그래서 존재하지 않는 유저로 테스트.
    result = sql_injection.sql_injection_easy.attempt({"username": "nonexistent' OR '1'='1"})
    assert result.success is False
    assert result.lens_rule_id == "comment_terminator"
    assert result.lens_passed_count == 2


def test_sqli_easy_malformed_input_falls_back_instead_of_crashing():
    result = sql_injection.sql_injection_easy.attempt({"username": 12345})
    assert result.success is False
    assert result.lens_rule_id == "fallback_unrecognized_input"


def test_sqli_medium_easy_style_payload_now_fails_at_filter():
    """Easy에서 통했던 정확한 대문자 OR가 Medium에서는 필터에 걸린다."""
    result = sql_injection.sql_injection_medium.attempt({"username": "admin' OR '1'='1' --"})
    assert result.success is False
    assert result.lens_rule_id == "filter_bypass"
    assert result.lens_passed_count == 1


def test_sqli_medium_case_varied_bypass_succeeds():
    result = sql_injection.sql_injection_medium.attempt({"username": "admin' oR '1'='1' --"})
    assert result.success is True


def test_sqli_medium_fails_at_always_true_after_surviving_filter():
    result = sql_injection.sql_injection_medium.attempt({"username": "admin' or"})
    assert result.success is False
    assert result.lens_rule_id == "always_true"
    assert result.lens_passed_count == 2


def test_sqli_medium_fails_at_comment_terminator():
    result = sql_injection.sql_injection_medium.attempt({"username": "nonexistent' or '1'='1"})
    assert result.success is False
    assert result.lens_rule_id == "comment_terminator"
    assert result.lens_passed_count == 3


# ---- #19 ExecutionGraph: 성공 시 실제 데이터로 채워진 유도 과정을 낸다 ----

def test_sqli_easy_success_builds_execution_graph():
    result = sql_injection.sql_injection_easy.attempt({"username": "admin' OR '1'='1' --"})
    g = result.execution_graph
    assert g is not None and g.shape == "derivation"
    # 페이로드가 조각으로 쪼개졌는지
    seg_ids = {s.id for s in g.payload_segments}
    assert {"quote", "logic", "comment"} <= seg_ids
    # 실제 반환된 행이 table 단계에 matched로 반영됐는지 (admin' OR ... -- 는 모든 행)
    table = next(s for s in g.steps if s.kind == "table")
    assert sum(1 for r in table.rows if r.matched) == 2
    verdict = next(s for s in g.steps if s.kind == "verdict")
    assert verdict.status == "success"


def test_sqli_medium_graph_includes_filter_bypass_step():
    result = sql_injection.sql_injection_medium.attempt({"username": "admin' oR '1'='1' --"})
    assert result.success is True
    step_ids = [s.id for s in result.execution_graph.steps]
    assert "filter" in step_ids  # medium만의 필터 우회 단계


def test_sqli_failure_has_no_execution_graph():
    result = sql_injection.sql_injection_easy.attempt({"username": "admin"})
    assert result.success is False
    assert result.execution_graph is None


# ---------------------------------------------------------------- Reflected XSS

def test_xss_easy_success():
    result = reflected_xss.reflected_xss_easy.attempt({"query": "<script>alert(1)</script>"})
    assert result.success is True


def test_xss_easy_fails_at_script_open():
    result = reflected_xss.reflected_xss_easy.attempt({"query": "hello"})
    assert result.success is False
    assert result.lens_rule_id == "script_open"


def test_xss_easy_fails_at_script_close():
    result = reflected_xss.reflected_xss_easy.attempt({"query": "<script>alert(1)"})
    assert result.success is False
    assert result.lens_rule_id == "script_close"


def test_xss_easy_malformed_input_falls_back_instead_of_crashing():
    result = reflected_xss.reflected_xss_easy.attempt({"query": 12345})
    assert result.success is False
    assert result.lens_rule_id == "fallback_unrecognized_input"


def test_xss_medium_easy_style_payload_now_fails_at_filter():
    result = reflected_xss.reflected_xss_medium.attempt({"query": "<script>alert(1)</script>"})
    assert result.success is False
    assert result.lens_rule_id == "filter_bypass"


def test_xss_medium_case_varied_bypass_succeeds_and_renders():
    result = reflected_xss.reflected_xss_medium.attempt({"query": "<ScRiPt>alert(1)</script>"})
    assert result.success is True
    # 실제 실행 경로(render)도 필터가 살아있는 태그를 그대로 통과시키는지 확인
    html = reflected_xss.reflected_xss_medium.render({"query": "<ScRiPt>alert(1)</script>"})
    assert "<ScRiPt>alert(1)</script>" in html


def test_xss_medium_fails_at_script_close_after_surviving_filter():
    result = reflected_xss.reflected_xss_medium.attempt({"query": "<ScRiPt>alert(1)"})
    assert result.success is False
    assert result.lens_rule_id == "script_close"


# ---------------------------------------------------------------- IDOR

def test_idor_easy_success():
    result = idor.idor_easy.attempt({"requested_id": 1043})
    assert result.success is True


def test_idor_easy_fails_at_different_resource():
    result = idor.idor_easy.attempt({"requested_id": 1042})
    assert result.success is False
    assert result.lens_rule_id == "different_resource"


def test_idor_easy_fails_at_resource_exists():
    result = idor.idor_easy.attempt({"requested_id": 9999})
    assert result.success is False
    assert result.lens_rule_id == "resource_exists"


def test_idor_easy_malformed_input_does_not_crash():
    """resource_exists가 unhashable 타입에 dict `in`을 쓰므로 TypeError 유발."""
    result = idor.idor_easy.attempt({"requested_id": ["not", "hashable"]})
    assert result.success is False
    assert result.lens_rule_id == "fallback_unrecognized_input"


def test_idor_easy_dead_guessable_rule_removed():
    """#18 결정(C): '추측 가능한 정수 ID' 규칙은 첫 실패 지점이 될 수 있는
    입력이 구조적으로 존재하지 않는 죽은 규칙이었다 (resource_exists를 통과하는
    값은 이미 int일 수밖에 없음). 규칙 체인에서 제거하고, 그 교훈은 성공
    시각화의 note로 옮겼다 (아래 test_idor_success_teaches_guessable_ids)."""
    rule_ids = [r.id for r in idor.idor_easy.rules]
    assert "guessable_id" not in rule_ids
    assert rule_ids == ["different_resource", "resource_exists"]


def test_idor_success_teaches_guessable_ids():
    """#18: 제거한 규칙이 가르치려던 '순차/추측 가능한 ID' 개념이 성공
    경로의 입력 단계 note로 살아남았는지 회귀 고정."""
    result = idor.idor_easy.attempt({"requested_id": 1043})
    assert result.success is True
    input_step = next(s for s in result.visualization if s.step == "input")
    assert input_step.note is not None
    assert "추측" in input_step.note


def test_idor_medium_success_requires_claimed_owner():
    result = idor.idor_medium.attempt({"requested_id": 1043, "claimed_user_id": 2001})
    assert result.success is True


def test_idor_medium_fails_without_correct_claim():
    result = idor.idor_medium.attempt({"requested_id": 1043, "claimed_user_id": 1})
    assert result.success is False
    assert result.lens_rule_id == "claims_correct_owner"


# ---------------------------------------------------------- Command Injection

def test_cmdi_labs_registered():
    assert {"command-injection-easy", "command-injection-medium"} <= REGISTRY.keys()


def test_cmdi_easy_success_simulates_output_and_builds_graph():
    result = command_injection.command_injection_easy.attempt({"host": "localhost; whoami"})
    assert result.success is True
    g = result.execution_graph
    assert g is not None and g.attack == "command_injection" and g.shape == "derivation"
    # 순수 시뮬레이션: whoami -> root 가 출력 단계에 반영됐는지
    output_step = next(s for s in g.steps if s.id == "output")
    assert "root" in output_step.spans[0].text
    seg_ids = {s.id for s in g.payload_segments}
    assert {"sep", "cmd"} <= seg_ids


def test_cmdi_easy_fails_at_separator():
    result = command_injection.command_injection_easy.attempt({"host": "localhost"})
    assert result.success is False
    assert result.lens_rule_id == "separator"


def test_cmdi_easy_fails_at_injected_command():
    result = command_injection.command_injection_easy.attempt({"host": "localhost;"})
    assert result.success is False
    assert result.lens_rule_id == "injected_command"


def test_cmdi_medium_semicolon_blocked_by_filter():
    """Easy에서 통하던 세미콜론이 Medium 필터에 걸린다."""
    result = command_injection.command_injection_medium.attempt({"host": "localhost; whoami"})
    assert result.success is False
    assert result.lens_rule_id == "filter_bypass"


def test_cmdi_medium_pipe_bypass_succeeds():
    result = command_injection.command_injection_medium.attempt({"host": "localhost | whoami"})
    assert result.success is True
    assert result.execution_graph is not None


def test_cmdi_never_runs_a_real_shell():
    """안전 회귀: 시뮬레이션이라 알 수 없는 명령도 크래시 없이 흉내낸 출력만 낸다."""
    result = command_injection.command_injection_easy.attempt({"host": "localhost; rm -rf /"})
    assert result.success is True
    output_step = next(s for s in result.execution_graph.steps if s.id == "output")
    assert "rm -rf /" in output_step.spans[0].text  # 실행이 아니라 문자열로만 반영
