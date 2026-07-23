import re
from typing import Callable, Optional

from app.core.lab import (
    CodeSpan,
    DerivSpan,
    DerivStep,
    ExecutionGraph,
    GraphSegment,
    Lab,
    LabMetadata,
    RuleCheck,
    SuccessDetail,
    VisualizationStep,
)

# Option A: 실제 subprocess를 절대 실행하지 않는 순수 시뮬레이션 (#4 스파이크에서
# 안전 설계로 확정). 입력 문자열을 파싱해 "진짜 셸이었다면 이렇게 됐을" 결과를
# 흉내낼 뿐이다. 실제 bash는 ;; ||| 같은 걸 더 엄격히 따지지만 그건 알려진 단순화.

_SEP_RE = re.compile(r"(\|\||&&|;|\||`|\$\()")

_SIM_OUTPUT = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/app",
    "ls": "app.py  config.yml  secret.key",
    "hostname": "payloadlab-server",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash  (…이하 생략…)",
}


def _identity_filter(host: str) -> str:
    return host


def _strip_semicolon(host: str) -> str:
    """Medium용 순진한 필터: 세미콜론만 지운다 (|, && 는 못 잡음)."""
    return host.replace(";", "")


def _split_injection(host: str) -> tuple[Optional[str], Optional[str], str]:
    """(separator, injected_command, base_host)를 반환. 구분자 없으면 (None, None, host)."""
    m = _SEP_RE.search(host)
    if not m:
        return None, None, host
    injected = host[m.end() :].strip().strip("`)").strip()
    return m.group(1), (injected or None), host[: m.start()].strip()


def _simulate(cmd: str) -> str:
    return _SIM_OUTPUT.get(cmd.strip(), f"(명령 '{cmd.strip()}' 이 서버에서 실행되어 출력을 반환)")


# ------------------------------------------------------------------ rules (Lens)


def _has_separator(payload: dict) -> bool:
    return _SEP_RE.search(payload.get("host", "")) is not None


def _has_injected_command(payload: dict) -> bool:
    _, injected, _ = _split_injection(payload.get("host", ""))
    return injected is not None


def _separator_survives_filter(payload: dict) -> bool:
    return _SEP_RE.search(_strip_semicolon(payload.get("host", ""))) is not None


# ------------------------------------------------------------- ExecutionGraph


_ROLE_STYLE = {"breakout": "taint", "injected": "taint"}


def _segment_host(host: str) -> list[GraphSegment]:
    m = _SEP_RE.search(host)
    if not m:
        return [GraphSegment(id="base", text=host, role="benign")]
    segs: list[GraphSegment] = []
    if host[: m.start()]:
        segs.append(GraphSegment(id="base", text=host[: m.start()], role="benign"))
    segs.append(GraphSegment(id="sep", text=host[m.start() : m.end()], role="breakout"))
    if host[m.end() :]:
        segs.append(GraphSegment(id="cmd", text=host[m.end() :], role="injected"))
    return segs


def _build_cmdi_graph(
    raw_host: str, sep: str, injected: str, base: str, output: str, has_filter: bool
) -> ExecutionGraph:
    segs = _segment_host(raw_host)

    steps: list[DerivStep] = [
        DerivStep(
            id="template",
            kind="query",
            label="① 서버가 실행하는 명령 틀",
            spans=[
                DerivSpan(text="ping -c 1 "),
                DerivSpan(text="여기", style="slot"),
            ],
            note="입력(여기)이 셸 명령에 그대로 이어붙는다",
        ),
        DerivStep(
            id="filled",
            kind="query",
            label="② 입력이 명령에 글자 그대로",
            spans=[DerivSpan(text="ping -c 1 ")]
            + [DerivSpan(text=s.text, group=s.id, style=_ROLE_STYLE.get(s.role, "")) for s in segs],
            note="입력이 명령 문자열의 일부가 되어 버린다",
        ),
    ]

    if has_filter:
        steps.append(
            DerivStep(
                id="filter",
                kind="query",
                label="②′ 순진한 필터를 통과",
                spans=[
                    DerivSpan(text="필터가 "),
                    DerivSpan(text=";", style="muted"),
                    DerivSpan(text="만 지움 → "),
                    DerivSpan(text=sep, group="sep", style="taint"),
                    DerivSpan(text="는 살아남음"),
                ],
                note="Medium의 필터는 세미콜론만 제거한다",
            )
        )

    steps.append(
        DerivStep(
            id="separate",
            kind="note",
            label="③ 셸이 구분자로 명령을 나눔",
            note=f"셸은 {sep} 를 만나면 앞뒤를 별개 명령으로 본다 → 원래 ping과 주입한 '{injected}'가 둘 다 실행된다.",
        )
    )
    steps.append(
        DerivStep(
            id="output",
            kind="query",
            label="④ 주입한 명령의 실제 출력",
            spans=[DerivSpan(text=f"$ {injected}\n{output}", group="cmd", style="taint")],
            note="주입한 명령이 서버 권한(root)으로 실행됐다",
        )
    )
    steps.append(
        DerivStep(
            id="verdict",
            kind="verdict",
            status="success",
            text=f"주입한 명령({injected})이 서버에서 실행됨 — Command Injection 성공",
        )
    )

    code = [
        CodeSpan(text='subprocess.run(f"ping -c 1 '),
        CodeSpan(text="{host}", group="sep"),
        CodeSpan(text='", shell=True)  # 입력을 셸에 그대로 넘김'),
    ]
    return ExecutionGraph(
        attack="command_injection",
        shape="derivation",
        payload_segments=segs,
        code_caption="취약한 명령 실행 (shell=True)",
        code=code,
        steps=steps,
    )


def _make_resolve(filter_fn: Callable[[str], str], route: str, has_filter: bool = False):
    def _resolve(payload: dict) -> tuple[bool, Optional[SuccessDetail]]:
        host = payload.get("host", "")
        # 순수 시뮬레이션: 실제 셸을 절대 실행하지 않고, 필터 적용 후 구분자/주입
        # 명령 유무만 문자열로 판정한다.
        filtered = filter_fn(host)
        sep, injected, base = _split_injection(filtered)
        if sep is None or injected is None:
            return False, None
        output = _simulate(injected)

        visualization = [
            VisualizationStep(step="input", label="사용자 입력값", value=host),
            VisualizationStep(
                step="processing", label="서버 라우터 또는 브라우저 처리 단계",
                value=f"셸이 {sep} 를 명령 구분자로 해석해 두 개의 명령으로 나눔",
            ),
            VisualizationStep(
                step="result", label="공격 성공 결과",
                value=f"주입한 명령 '{injected}' 실행 출력: {output}",
            ),
        ]

        return True, SuccessDetail(
            visualization=visualization,
            execution_graph=_build_cmdi_graph(host, sep, injected, base, output, has_filter),
        )

    return _resolve


command_injection_easy = Lab(
    metadata=LabMetadata(
        id="command-injection-easy",
        name="Command Injection (Easy)",
        category="command_injection",
        difficulty="easy",
        route="/labs/command-injection-easy",
    ),
    rules=[
        RuleCheck("separator", "명령을 잇는 특수문자(;, |, && 등)가 없습니다.", _has_separator),
        RuleCheck("injected_command", "구분자는 넣었지만 뒤에 실행할 명령이 없습니다.", _has_injected_command),
    ],
    resolve=_make_resolve(_identity_filter, "/labs/command-injection-easy"),
)

command_injection_medium = Lab(
    metadata=LabMetadata(
        id="command-injection-medium",
        name="Command Injection (Medium)",
        category="command_injection",
        difficulty="medium",
        route="/labs/command-injection-medium",
    ),
    rules=[
        RuleCheck("separator", "명령을 잇는 특수문자(;, |, && 등)가 없습니다.", _has_separator),
        RuleCheck("filter_bypass", "필터가 세미콜론(;)을 제거합니다. | 나 && 로 우회해보세요.", _separator_survives_filter),
        RuleCheck("injected_command", "구분자는 넣었지만 뒤에 실행할 명령이 없습니다.", _has_injected_command),
    ],
    resolve=_make_resolve(_strip_semicolon, "/labs/command-injection-medium", has_filter=True),
)
