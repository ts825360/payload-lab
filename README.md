# attack-lens

> ⚠️ 이 프로젝트는 아직 기획/설계 교차검증 단계입니다. 실행 가능한 코드는 아직 없고, 전체 설계와 논의는 GitHub 이슈에서 진행 중입니다.

## 이게 뭔가요

DVWA 같은 웹 공격 실습 도구를 참고하되, **왜 공격이 성공했는지 / 왜 실패했는지**를 초보자도 이해할 수 있게 만드는 교육용 웹 공격 실습 플랫폼입니다.

- 공격에 성공하면 → 입력값이 서버/브라우저에서 어떻게 처리되어 공격으로 이어졌는지 **시각화**로 보여줍니다.
- 공격에 실패하면 → **Lens**가 어떤 조건이 부족해서 실패했는지 규칙 기반으로 진단합니다.

전체 결과물은 로컬 Docker 환경에서만 실행되는 것을 전제로 합니다. 의도적으로 취약한 앱이므로 외부 공개 서버로 운영하지 않습니다.

## "Lens"라는 이름은 어디서 왔나요

Lens는 VS Code의 인기 확장 프로그램 **[Error Lens](https://marketplace.visualstudio.com/items?itemName=usernamehw.errorlens)**에서 아이디어를 가져온 이름입니다. 원래 코드 에디터는 에러가 나면 밑줄만 긋고, 그 이유를 보려면 마우스를 올리거나 별도 패널을 열어야 합니다. Error Lens는 그 이유를 에러가 난 줄 바로 옆에 즉시 텍스트로 띄워줘서, 별도 클릭 없이 바로 원인을 알 수 있게 해주는 도구입니다.

팀원 로메인의 해커톤 프로젝트 [loupe](https://github.com/RomainHartmann/loupe)(프랑스어로 "돋보기")도 같은 발상입니다 — 기사 속에서 의심스러운 문장에 바로 밑줄을 긋고 그 옆에 이유를 보여줍니다.

우리 프로젝트의 Lens는 이 발상을 보안 실습에 그대로 적용한 것입니다. 공격 payload가 실패하면, Lens가 "정확히 어떤 조건이 부족했는지"를 그 자리에서 바로 보여줍니다 — Error Lens가 코드 에러를 그 줄에서 바로 보여주듯이, 실패한 공격의 원인을 별도 검색이나 AI 질문 없이 바로 보여주는 것이 목표입니다.

## 지금 상태 — 여기부터 보세요

아직 구현 전, 기획을 교차검증하고 세부 설계를 결정하는 단계입니다. 전체 그림과 모든 설계 논의는 Issues 탭에 정리되어 있고, 아래 두 이슈가 고정(pinned)되어 있습니다.

- 📌 [#12 프로젝트 비전과 전체 기획](https://github.com/ts825360/attack-lens/issues/12) — 무엇을, 왜 만드는지와 전체 설계, 그리고 하위 논의 이슈 전체 목록을 읽는 순서대로 정리
- 📌 [#13 깃허브 사용 방법](https://github.com/ts825360/attack-lens/issues/13) — 깃허브의 이슈/브랜치/풀 리퀘스트를 처음 써보는 팀원을 위한 단계별 안내

새로 합류한 팀원은 `#13` → `#12` 순서로 읽는 것을 권장합니다.

## 예정 기술 스택

Python (FastAPI) · React · SQLite/PostgreSQL · Docker / Docker Compose

(확정 사항이 아니며, 세부 결정 현황은 [#12](https://github.com/ts825360/attack-lens/issues/12)를 참고하세요.)

## 참고 자료

- [docs/superpowers/specs/2026-07-15-web-attack-lab-design.md](docs/superpowers/specs/2026-07-15-web-attack-lab-design.md) — 초기 설계 문서 초안
- [docs/references/romain-loupe-agent-prompts.md](docs/references/romain-loupe-agent-prompts.md) — 참고한 [loupe](https://github.com/RomainHartmann/loupe) 저장소의 프롬프트/에이전트 운영 패턴 정리
