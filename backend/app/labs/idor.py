from typing import Optional

from app.core.lab import (
    CodeSpan,
    DerivStep,
    ExecutionGraph,
    GraphSegment,
    Lab,
    LabMetadata,
    RelArrow,
    RelObject,
    RuleCheck,
    ServerState,
    SuccessDetail,
    TableState,
    VariableState,
    VisualizationStep,
)

# 로그인한 사용자는 항상 1042번 주문의 소유자라고 가정 (데모용 고정 세션)
_CURRENT_USER_ID = 1042
_ORDER_IDS = [1042, 1043]
_ORDERS = {
    1042: {"owner_id": 1042, "item": "노트북 파우치", "address": "본인 주소"},
    1043: {"owner_id": 2001, "item": "기계식 키보드", "address": "다른 사용자 주소"},
}

_CODE_SNIPPET_EASY = (
    "order = orders.get(requested_id)\n"
    "# owner_id == current_user.id 검사가 없음"
)

_CODE_SNIPPET_MEDIUM = (
    "order = orders.get(requested_id)\n"
    "# 세션이 아니라 요청 파라미터 claimed_user_id를 그대로 신뢰함\n"
    "if payload['claimed_user_id'] == order['owner_id']:\n"
    "    return order"
)


def _requested_someone_elses_resource(payload: dict) -> bool:
    return payload.get("requested_id") != _CURRENT_USER_ID

def _resource_exists(payload: dict) -> bool:
    return payload.get("requested_id") in _ORDERS

def _claims_correct_owner(payload: dict) -> bool:
    requested_id = payload.get("requested_id")
    if requested_id not in _ORDERS:
        return False
    return payload.get("claimed_user_id") == _ORDERS[requested_id]["owner_id"]


def _visualization_and_state(payload: dict, requested_id: int) -> tuple[list[VisualizationStep], ServerState]:
    order = _ORDERS[requested_id]
    visualization = [
        VisualizationStep(
            step="input", label="사용자 입력값",
            value=f"주문번호를 {_CURRENT_USER_ID}에서 {requested_id}로 변경",
            note=f"주문번호가 {_CURRENT_USER_ID}, {requested_id}처럼 연속된 정수라, 로그인만 하면 다음 번호를 그냥 추측해서 넣어볼 수 있습니다. 이 '추측 가능한 순차 ID'가 IDOR이 통하는 핵심 조건입니다.",
        ),
        VisualizationStep(step="request", label="요청 또는 브라우저 이벤트", value=f"GET /labs/idor/attempt?order_id={requested_id}"),
        VisualizationStep(
            step="processing", label="서버 라우터 또는 브라우저 처리 단계",
            value="서버는 로그인 여부만 확인하고, 요청한 주문번호가 이 사용자 소유인지는 확인하지 않음",
        ),
        VisualizationStep(step="result", label="공격 성공 결과", value=f"다른 사용자의 주문 정보 노출: {order}"),
    ]
    variables = [
        VariableState(name="current_user_id", value=str(_CURRENT_USER_ID)),
        VariableState(name="requested_id", value=str(requested_id), highlight=str(requested_id)),
    ]
    if "claimed_user_id" in payload:
        variables.append(
            VariableState(name="claimed_user_id", value=str(payload["claimed_user_id"]), highlight=str(payload["claimed_user_id"]))
        )
    server_state = ServerState(
        variables=variables,
        table=TableState(
            name="orders",
            columns=["order_id", "owner_id", "item"],
            rows=[[str(oid), str(_ORDERS[oid]["owner_id"]), _ORDERS[oid]["item"]] for oid in _ORDER_IDS],
            matched_row_indices=[_ORDER_IDS.index(requested_id)],
        ),
    )
    return visualization, server_state


# --------------------------------------------------------------------------
# ExecutionGraph 빌더 (#19): IDOR은 변형되는 문자열이 없어(부재형) "관계 스냅샷"
# 으로 그린다 -- 주인 화살표가 나를 가리키느냐 남을 가리키느냐, 그리고 서버가 그
# 관계를 확인하지 않았다는 것을 보여준다. 성공(=남의 것 접근) 시에만 생성된다.
# --------------------------------------------------------------------------


def _build_idor_graph(requested_id: int, claimed_user_id: Optional[int] = None) -> ExecutionGraph:
    real_owner = _ORDERS[requested_id]["owner_id"]

    steps: list[DerivStep] = [
        DerivStep(
            id="request",
            kind="note",
            label="① 번호만 바꿔 요청",
            note=(
                f"주문번호를 내 것({_CURRENT_USER_ID})에서 {requested_id}로 바꿔 요청. "
                f"{_CURRENT_USER_ID}, {requested_id}처럼 순차 정수라 다음 번호를 그냥 추측할 수 있다."
            ),
        ),
        DerivStep(
            id="missing",
            kind="note",
            style="missing",
            label="② 소유권 검사가 없음",
            note="서버는 로그인만 확인하고, 이 주문이 내 것인지(주인 == 나)는 확인하지 않는다.",
        ),
    ]

    if claimed_user_id is not None:
        steps.append(
            DerivStep(
                id="claimed",
                kind="note",
                label="②′ 서버가 내 주장을 그대로 믿음",
                note=(
                    f"세션 대신 내가 보낸 claimed_user_id={claimed_user_id}를 그대로 신뢰한다. "
                    f"진짜 주인 번호({real_owner})만 맞춰 보내면 통과된다."
                ),
            )
        )

    steps.append(
        DerivStep(
            id="relations",
            kind="relations",
            label="③ 주인 화살표가 누구를 가리키나",
            note="내 주문의 주인 화살표는 나를, 요청한 주문의 주인 화살표는 남을 가리킨다 — 서버는 이 화살표를 확인하지 않았다.",
            objects=[
                RelObject(id="order_req", title=f"주문 {requested_id}", subtitle=f"주인 = {real_owner}", tone="other"),
                RelObject(id="owner_other", title=f"사용자 {real_owner}", subtitle="이 주문의 주인 (남)", tone="other"),
                RelObject(id="order_mine", title=f"주문 {_CURRENT_USER_ID}", subtitle=f"주인 = {_CURRENT_USER_ID}", tone="mine"),
                RelObject(id="me", title="나 (로그인)", subtitle=f"user {_CURRENT_USER_ID}", tone="mine"),
            ],
            arrows=[
                RelArrow(source="order_req", target="owner_other", label="주인", tone="other"),
                RelArrow(source="order_mine", target="me", label="주인", tone="mine"),
            ],
        )
    )
    steps.append(
        DerivStep(
            id="verdict",
            kind="verdict",
            status="success",
            text=f"남의 주문({requested_id}) 정보가 그대로 노출됨 — IDOR 성공",
        )
    )

    code_snippet = _CODE_SNIPPET_MEDIUM if claimed_user_id is not None else _CODE_SNIPPET_EASY
    code = [CodeSpan(text=code_snippet)]
    return ExecutionGraph(
        attack="idor",
        shape="relational",
        payload_segments=[GraphSegment(id="reqid", text=str(requested_id), role="injected")],
        code_caption="취약한 주문 조회",
        code=code,
        steps=steps,
    )


def _resolve_easy(payload: dict) -> tuple[bool, Optional[SuccessDetail]]:
    requested_id = payload.get("requested_id")
    if not (_requested_someone_elses_resource(payload) and _resource_exists(payload)):
        return False, None
    visualization, server_state = _visualization_and_state(payload, requested_id)
    return True, SuccessDetail(
        visualization=visualization,
        server_state=server_state,
        code_snippet=_CODE_SNIPPET_EASY,
        execution_graph=_build_idor_graph(requested_id),
    )


def _resolve_medium(payload: dict) -> tuple[bool, Optional[SuccessDetail]]:
    requested_id = payload.get("requested_id")
    if not (
        _requested_someone_elses_resource(payload)
        and _resource_exists(payload)
        and _claims_correct_owner(payload)
    ):
        return False, None
    visualization, server_state = _visualization_and_state(payload, requested_id)
    return True, SuccessDetail(
        visualization=visualization,
        server_state=server_state,
        code_snippet=_CODE_SNIPPET_MEDIUM,
        execution_graph=_build_idor_graph(requested_id, claimed_user_id=payload.get("claimed_user_id")),
    )


idor_easy = Lab(
    metadata=LabMetadata(
        id="idor-easy",
        name="IDOR (Easy)",
        category="idor",
        difficulty="easy",
        route="/labs/idor-easy",
    ),
    rules=[
        RuleCheck("different_resource", "본인 소유 리소스를 요청했습니다. 다른 주문번호로 바꿔서 요청해보세요.", _requested_someone_elses_resource),
        RuleCheck("resource_exists", "존재하지 않는 주문번호입니다.", _resource_exists),
    ],
    resolve=_resolve_easy,
)

idor_medium = Lab(
    metadata=LabMetadata(
        id="idor-medium",
        name="IDOR (Medium)",
        category="idor",
        difficulty="medium",
        route="/labs/idor-medium",
    ),
    rules=[
        RuleCheck("different_resource", "본인 소유 리소스를 요청했습니다. 다른 주문번호로 바꿔서 요청해보세요.", _requested_someone_elses_resource),
        RuleCheck("resource_exists", "존재하지 않는 주문번호입니다.", _resource_exists),
        RuleCheck("claims_correct_owner", "이 서버는 세션 대신 요청에 실린 claimed_user_id를 그대로 믿습니다. 그 주문의 실제 소유자 ID로 맞춰서 같이 보내보세요.", _claims_correct_owner),
    ],
    resolve=_resolve_medium,
)
