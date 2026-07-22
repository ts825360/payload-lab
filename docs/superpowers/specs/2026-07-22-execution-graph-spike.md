# 실행 다이어그램(Execution Graph) 스키마 스파이크

## 목적

성공 화면을 "변수/코드/흐름 3탭"에서 **한 번의 스크롤로 이어지는 관계 그래프**로 바꾼다.
핵심 요구:

1. Python Tutor처럼 **객체·데이터가 화살표로 연결**되는 교육용 시각화 (debug panel 아님).
2. **Payload ↔ Diagram ↔ Code 양방향 하이라이트** — 이 프로젝트의 핵심 차별점, 절대 제거 금지.
3. 탭 제거, `Payload → Lens → Code → Execution Diagram → Result` 단일 스크롤.
4. SQLi뿐 아니라 XSS, IDOR, 그리고 향후 Command Injection · Path Traversal까지 **같은 스키마**로 확장.

스파이크의 질문: **하나의 노드/엣지 스키마가 이 공격들에 다 맞는가? 어디서 깨지는가?**
(결정을 내리기 전에 실제 구조에 먼저 대보는 것 — #5/#9와 동일한 verify-before-decide.)

---

## 제안 스키마 (백엔드가 내려줄 계약)

```
ExecutionGraph:
  attack: str
  payload_segments: [Segment]     # 입력을 "의미 있는 조각"으로 분할
  nodes: [Node]
  edges: [Edge]                   # 노드 간 데이터 이동 (화살표)
  boundaries: [Boundary]          # 선택: 신뢰 경계 (예: 서버 → 브라우저)
  code: CodeRef                   # 취약 코드 + 앵커(하이라이트 대상 span)
  data: DataRef?                  # 선택: 결과 테이블/행

Segment: { id, text, role }       # role: benign|breakout|logic|comment|injected
Node:    { id, kind, title, subtitle, taint: bool, severity, status, side }
          # kind: value|operation|sink|missing|result
          # severity: "" | danger(=취약 지점)
          # status: "" | success | blocked
          # side: server | browser   (경계 레이아웃용)
Edge:    { from, to, label? }
Boundary:{ after_node_id, label }
CodeRef: { language, lines: [{ text, anchors: [{id, span:[a,b]}] }] }
DataRef: { table, columns, rows: [{ id, cells, matched: bool }] }

links: [[id_a, id_b], ...]        # ★ 핵심: 모든 요소 id를 잇는 "무방향" 연결 집합
```

### ★ 양방향 하이라이트를 "공짜로" 만드는 한 가지 결정

세그먼트·노드·코드앵커·데이터행이 **모두 전역 고유 id**를 갖고, 그들 사이의 연관을
**무방향 `links` 하나**로 표현한다. UI 규칙은 단 하나:

> 어떤 요소 E에 hover/focus하면, E와 `links`로 이어진 모든 이웃을 함께 강조한다.

이렇게 하면 "payload→node"와 "node→payload"를 따로 배선할 필요가 없다 —
같은 링크를 양쪽으로 읽을 뿐이라 **양방향이 구조적으로 보장**된다.
(hover=탐색, click=고정(pin)해서 읽기, focus=키보드/터치 동일 동작.)

---

## 검증 1 — SQL Injection  `admin' OR '1'='1' --`  (파이프라인 형)

```
segments: [admin][ '(breakout) ][ OR '1'='1'(logic) ][ --(comment) ]

[페이로드]taint
   ↓
[username 변수]taint
   ↓
[문자열 연결]sink·danger      ← 취약 지점 (이스케이프 없음)
   ↓
[완성된 SQL]taint
   ↓
[WHERE 평가] → 항상 TRUE
   ↓
[반환된 행] → admin, guest
   ↓
[로그인 성공]result

links:
  '(breakout)  — 문자열 연결 노드 — 코드앵커 {username}
  OR '1'='1'   — WHERE 평가 노드
  --(comment)  — 코드앵커 (AND password=... 를 주석 처리)
  완성된 SQL   — 코드앵커 {username}
  반환된 행    — 데이터행 r0, r1
```

**결과: 잘 맞음.** 파이프라인 형태 그대로. ✔

---

## 검증 2 — Reflected XSS  `<script>alert(document.domain)</script>`  (경계 반사 형)

```
segments: [ <script>(breakout) ][ alert(...)(injected) ][ </script> ]

── 서버 ──────────────────────────
[페이로드]taint → [query 변수]taint → [HTML 문자열 삽입]sink·danger → [완성된 HTML 문서]taint
──────── 신뢰 경계: 서버 → 브라우저 ────────   ← Boundary
── 브라우저 ──────────────────────
[HTML 파서] → [<script> 태그 인식] → [JS 실행]result   ← 실제 iframe에 연결
```

**여기서 naive 파이프라인은 깨진다.** XSS의 본질은 "서버가 만든 문자열이 **브라우저에서 코드가 된다**"인데,
이걸 표현하려면 `Boundary`(서버→브라우저 구분선)와 `Node.side`가 필요하다.
마지막 `[JS 실행]` 노드는 특별 링크로 **지금의 실제 실행 iframe**에 연결한다.
→ 스키마에 `boundaries` + `side`를 넣으면 담긴다. ✔ (없었으면 깨졌을 지점 — 스파이크가 잡아낸 것)

---

## 검증 3 — IDOR  `order_id=1043`  (빠진 검사 형)

```
segments: [ 1043 ]

[페이로드]taint → [requested_id 변수]taint → [로그인 확인]통과
   → [소유권 검사 (없음)]kind=missing·점선   ← 취약의 정체는 "있어야 할 노드의 부재"
   → [orders.get(1043)] → [남의 주문 반환] → [정보 노출]result

links:
  소유권 검사(없음) — 코드앵커 `# owner_id == current_user.id 검사가 없음`
                       (이 주석이 코드에 실제로 있음 → 부재를 실물에 앵커링 가능)
  1043 — orders.get 노드 — 데이터행
```

**IDOR는 변환이 아니라 분기의 부재다.** 파이프라인으로 그리면 어색하지만,
`Node.kind="missing"`(점선 유령 노드)을 두면 "이 검사가 있었다면 여기서 막혔다"를 정확히 보여준다.
게다가 그 부재를 코드의 "검사 없음" 주석에 앵커링할 수 있어 링크도 성립한다.
→ `kind:"missing"` 프리미티브로 담긴다. ✔ (두 번째 strain 지점 — 역시 스파이크가 잡음)

---

## 확장성 — Command Injection · Path Traversal

- **Command Injection** (`; cat /etc/passwd` 류): 입력 → 셸 명령 문자열 연결(sink) → 셸 파서 → 명령 실행.
  **SQLi와 완전히 같은 파이프라인 형.** 세그먼트(정상 인자 / `;` breakout / 주입 명령)도 대응. ✔
  (`#4` 스파이크에서 안전 설계까지 검증된 Phase 2 1순위 후보라 실제로 붙일 값어치가 큼.)
- **Path Traversal** (`../../etc/passwd`): 입력 → 경로 결합(sink) → 파일시스템 해석 → 파일 읽기 → 내용 반환.
  역시 파이프라인 형. `../` = traversal 세그먼트. ✔

둘 다 SQLi 틀을 그대로 재사용한다. 새 공격을 붙일 때 필요한 건 대개 **데이터만**(노드/링크 기술),
새 렌더 코드가 아니다 — 이게 "같은 철학으로 확장"의 실제 의미.

---

## 스파이크 결론

**하나의 스키마가 다섯 공격을 다 담는다 — 단, 두 개의 프리미티브를 추가해야만.**

| 공격 | 모양 | 필요한 것 |
|------|------|-----------|
| SQL Injection | 파이프라인 | 기본 노드/엣지 |
| Command Injection | 파이프라인 | 기본 |
| Path Traversal | 파이프라인 | 기본 |
| Reflected XSS | 경계 반사 | `boundaries` + `Node.side` |
| IDOR | 빠진 검사 | `Node.kind="missing"` |

naive 선형 파이프라인으로 굳혔다면 XSS와 IDOR에서 깨졌을 것이다.
세 공격에 먼저 대본 덕분에 그걸 만들기 전에 잡았다.

**오라클은 그대로.** 성공/실패 판정은 지금처럼 진짜 SQLite·진짜 iframe에서 나온다.
ExecutionGraph는 그 진짜 실행을 *서술*하는 저자 데이터이고, 반환된 행·반사된 HTML 같은
런타임 값은 실제 값을 그대로 채운다. "패턴매칭 아님"의 정직성은 유지된다.

---

## 결정 대기 (스파이크가 꺼낸 항목)

1. ExecutionGraph가 기존 `visualization`/`server_state`/`code_snippet` **세 필드를 대체**(단일 소스)한다 → 탭 컴포넌트 3종 은퇴. (권장)
2. `missing` 노드 = 점선 유령 노드로 렌더. (권장)
3. XSS 경계 = 서버/브라우저 가로 구분선. (권장)
4. 상호작용: hover=강조, click=고정, focus=키보드 동일. 무방향 `links` 한 벌로 양방향 구현.
5. Lens는 구조 유지 · 문안만 개선 (별도 작업).
6. 구현 순서: 백엔드 스키마 → SQLi 렌더 → XSS(경계)·IDOR(유령) 순으로 실제 데이터에 맞춰 검증.
