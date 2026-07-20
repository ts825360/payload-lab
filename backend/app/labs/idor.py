from typing import Optional

from app.core.lab import AttemptResult, Lab, LabMetadata, RuleCheck, VisualizationStep

# 로그인한 사용자는 항상 1042번 주문의 소유자라고 가정 (데모용 고정 세션)
_CURRENT_USER_ID = 1042
_ORDERS = {
    1042: {"owner_id": 1042, "item": "노트북 파우치", "address": "본인 주소"},
    1043: {"owner_id": 2001, "item": "기계식 키보드", "address": "다른 사용자 주소"},
}


def _requested_someone_elses_resource(payload: dict) -> bool:
    return payload.get("requested_id") != _CURRENT_USER_ID

def _resource_exists(payload: dict) -> bool:
    return payload.get("requested_id") in _ORDERS

def _id_is_guessable(payload: dict) -> bool:
    return isinstance(payload.get("requested_id"), int)


def _resolve(payload: dict) -> tuple[bool, Optional[list[VisualizationStep]]]:
    requested_id = payload.get("requested_id")
    if not (_requested_someone_elses_resource(payload) and _resource_exists(payload) and _id_is_guessable(payload)):
        return False, None
    order = _ORDERS[requested_id]
    return True, [
        VisualizationStep(step="input", label="사용자 입력값", value=f"주문번호를 {_CURRENT_USER_ID}에서 {requested_id}로 변경"),
        VisualizationStep(step="request", label="요청 또는 브라우저 이벤트", value=f"GET /labs/idor-easy/attempt?order_id={requested_id}"),
        VisualizationStep(
            step="processing", label="서버 라우터 또는 브라우저 처리 단계",
            value="서버는 로그인 여부만 확인하고, 요청한 주문번호가 이 사용자 소유인지는 확인하지 않음",
        ),
        VisualizationStep(
            step="transformation", label="취약한 변환",
            value=f"orders[{requested_id}] 조회 -- 소유자 조건(owner_id == current_user) 없이 그대로 반환",
            note="있어야 할 소유권 검사가 빠져서, 다른 사용자의 자원이 그대로 조회됩니다.",
        ),
        VisualizationStep(step="result", label="공격 성공 결과", value=f"다른 사용자의 주문 정보 노출: {order}"),
        VisualizationStep(
            step="vulnerable_code", label="취약 코드 핵심 줄",
            value="order = orders.get(requested_id)  # owner_id == current_user.id 검사 없음",
        ),
    ]


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
        RuleCheck("guessable_id", "다른 사용자의 리소스를 요청했지만 ID가 정수 형태가 아니라 추측할 수 없습니다.", _id_is_guessable),
    ],
    resolve=_resolve,
)
