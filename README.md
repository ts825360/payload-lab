# attack-lens

> ⚠️ 이 프로젝트는 아직 기획/설계 교차검증 단계입니다. 실행 가능한 코드는 아직 없고, 전체 설계와 논의는 GitHub 이슈에서 진행 중입니다.

## 이게 뭔가요

DVWA 같은 웹 공격 실습 도구를 참고하되, **왜 공격이 성공했는지 / 왜 실패했는지**를 초보자도 이해할 수 있게 만드는 교육용 웹 공격 실습 플랫폼입니다.

- 공격에 성공하면 → 입력값이 서버/브라우저에서 어떻게 처리되어 공격으로 이어졌는지 **시각화**로 보여줍니다.
- 공격에 실패하면 → **Lens**가 어떤 조건이 부족해서 실패했는지 규칙 기반으로 진단합니다.

전체 결과물은 로컬 Docker 환경에서만 실행되는 것을 전제로 합니다. 의도적으로 취약한 앱이므로 외부 공개 서버로 운영하지 않습니다.

## 지금 상태 — 여기부터 보세요

아직 구현 전, 기획을 교차검증하고 세부 설계를 결정하는 단계입니다. 전체 그림과 모든 설계 논의는 Issues 탭에 정리되어 있고, 아래 두 이슈가 고정(pinned)되어 있습니다.

- 📌 [#12 프로젝트 비전과 전체 기획](https://github.com/ts825360/attack-lens/issues/12) — 무엇을, 왜 만드는지와 전체 설계, 그리고 하위 논의 이슈 전체 목록을 읽는 순서대로 정리
- 📌 [#13 깃허브 사용 방법](https://github.com/ts825360/attack-lens/issues/13) — 깃허브의 이슈/브랜치/풀 리퀘스트를 처음 써보는 팀원을 위한 단계별 안내

새로 합류한 팀원은 `#13` → `#12` 순서로 읽는 것을 권장합니다.

## 예정 기술 스택

FastAPI · React · SQLite/PostgreSQL · Docker / Docker Compose

(확정 사항이 아니며, 세부 결정 현황은 [#12](https://github.com/ts825360/attack-lens/issues/12)를 참고하세요.)

## 참고 자료

- [docs/superpowers/specs/2026-07-15-web-attack-lab-design.md](docs/superpowers/specs/2026-07-15-web-attack-lab-design.md) — 초기 설계 문서 초안
- [docs/references/romain-loupe-agent-prompts.md](docs/references/romain-loupe-agent-prompts.md) — 참고한 [loupe](https://github.com/RomainHartmann/loupe) 저장소의 프롬프트/에이전트 운영 패턴 정리
