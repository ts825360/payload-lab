# PayloadLab

> ⚠️ 이 앱은 **의도적으로 취약**합니다. **로컬에서만** 실행하고, 외부에 공개하거나 여기서 배운 기법을 실제 서비스에 쓰지 마세요.

**공격을 직접 넣어보고, 왜 됐는지·왜 안 됐는지를 눈으로 이해하는 웹 공격 실습 랩.**

DVWA 같은 도구는 "취약한 표적"만 줍니다. PayloadLab은 한 걸음 더 갑니다 — 공격이 **성공하면** 입력이 어떻게 공격이 됐는지 다이어그램으로, **실패하면** 무엇이 빠졌는지 Lens가 짚어줍니다.

> 🖼️ 스크린샷은 UI 리디자인 마무리 후 추가됩니다.
<!-- ![PayloadLab 실행 화면](docs/images/hero.png) -->

## 이게 다른 점

- **성공 → 실행 다이어그램.** 한 번의 스크롤로, 내 입력이 서버에서 단계별로 어떻게 처리돼 공격이 됐는지 본다. 페이로드 · 코드 · 다이어그램이 서로 연결돼 하이라이트된다.
- **실패 → Lens.** 어떤 조건이 빠져서 실패했는지 그 자리에서 짚어준다.
- **진짜로 실행한다 (패턴매칭 아님).** SQLi는 실제 SQLite에 진짜 쿼리를 실행하고, XSS는 서버가 돌려준 페이지를 브라우저가 iframe으로 진짜 로드해 `<script>`가 실제로 실행된다. (Command Injection만 안전을 위해 시뮬레이션.)

<!-- ![성공 시 실행 다이어그램과 Lens](docs/images/diagram.png) -->

## 랩 목록

**4개 공격 × Easy/Medium = 8개 랩**, 전부 동작합니다.

| 공격 | 무엇을 배우나 |
|---|---|
| SQL Injection | 실제 SQLite에 취약한 로그인 쿼리를 실행 |
| Reflected XSS | 서버가 되돌려준 HTML을 브라우저가 진짜로 실행 |
| IDOR | 세션 대신 클라이언트가 보낸 값을 그대로 믿는 취약점 |
| Command Injection | 셸 명령 주입 (안전을 위해 실제 실행 대신 시뮬레이션) |

Medium은 전부 "Easy와 같은 기법 + 순진한 필터 하나를 대소문자 등으로 우회"하는 구조입니다.

## 실행

```bash
docker compose up --build
```

- 프론트엔드: http://localhost:5173
- 백엔드 API: http://localhost:8000

### 왜 로컬 전용인가

형식적 경고가 아닙니다 — 앱 안에 **진짜로 동작하는 공격 통로**가 있습니다. 예를 들어 XSS 랩의 `GET /labs/{id}/render`는 입력을 이스케이프 없이 그대로 HTML로 돌려주는 실제 reflected XSS입니다. 앱 안에서는 sandbox iframe에 가두지만, 이 URL을 브라우저에서 직접 열면 아무 격리 없이 스크립트가 실행됩니다. 공개 네트워크에 올리면 실습용 취약점이 그대로 남에게 열립니다.

## 기술 스택

Python (FastAPI) · React (Vite) · SQLite · Docker

## 이름 "Lens"

VS Code의 [Error Lens](https://marketplace.visualstudio.com/items?itemName=usernamehw.errorlens)에서 이름을 땄습니다 — 에러의 이유를 그 자리에 바로 띄워, 클릭 없이 원인을 알게 해주는 확장입니다. PayloadLab의 Lens는 같은 발상을 **"공격이 왜 실패했나"** 에 적용한 것입니다.

## 더 알아보기

- 새로 합류했다면 → [#13 깃허브 사용법](https://github.com/ts825360/payload-lab/issues/13) → [#12 프로젝트 비전](https://github.com/ts825360/payload-lab/issues/12) 순서로 읽으세요.
- 기여 규칙 → [이슈 작성·운영 가이드](docs/issue-guide.md)
- 어떻게 여기까지 왔나 → [개발 여정과 시행착오](docs/project-journey.md)
