"""Saída dos alertas: texto no terminal, Markdown (relatório) ou JSON (integração)."""

from __future__ import annotations

import json

from .parser import ParseStats
from .rules import Alert

COLORS = {"critica": "\033[1;41m", "alta": "\033[1;31m", "media": "\033[33m", "baixa": "\033[36m"}
RESET = "\033[0m"
LABEL = {"critica": "CRÍTICA", "alta": "ALTA", "media": "MÉDIA", "baixa": "BAIXA"}


def _summary(alerts: list[Alert]) -> str:
    counts = {s: 0 for s in LABEL}
    for a in alerts:
        counts[a.severity] += 1
    return " · ".join(f"{LABEL[s]} {n}" for s, n in counts.items() if n)


def _mitre(a: Alert) -> str:
    return ", ".join(f"{tid} {name}" for tid, name in a.mitre)


def render_text(alerts: list[Alert], stats: ParseStats, color: bool = False) -> str:
    out = [f"{stats.lines} linhas lidas, {stats.events} eventos de autenticação, "
           f"{len(alerts)} alerta(s)" + (f"  [{_summary(alerts)}]" if alerts else "")]
    for i, a in enumerate(alerts, 1):
        sev = f"[{LABEL[a.severity]}]"
        if color:
            sev = COLORS[a.severity] + sev + RESET
        out += ["", f"{i}. {sev} {a.rule}: {a.title}",
                f"   Origem:   {a.entity}",
                f"   Período:  {a.first:%d/%m %H:%M:%S} → {a.last:%d/%m %H:%M:%S}"
                f"  ({a.count} evento(s))",
                f"   MITRE:    {_mitre(a)}",
                f"   Ação N1:  {a.action}",
                "   Evidência:"]
        out += [f"     L{e.line_no}: {e.raw}" for e in a.evidence[:5]]
        if len(a.evidence) > 5:
            out.append(f"     ... e mais {len(a.evidence) - 5} linha(s)")
    if not alerts:
        out.append("Nenhum alerta. Isso não prova que não houve ataque: só que nenhuma "
                   "regra disparou com os limites atuais.")
    return "\n".join(out)


def render_markdown(alerts: list[Alert], stats: ParseStats, source: str) -> str:
    out = ["# Relatório de triagem: mini-siem", "",
           f"- **Fonte:** `{source}`",
           f"- **Linhas lidas:** {stats.lines} · **eventos de autenticação:** {stats.events}",
           f"- **Alertas:** {len(alerts)}" + (f" ({_summary(alerts)})" if alerts else ""),
           "", "| # | Severidade | Regra | Origem | Período | MITRE ATT&CK |",
           "|---|---|---|---|---|---|"]
    for i, a in enumerate(alerts, 1):
        out.append(f"| {i} | {LABEL[a.severity]} | {a.rule} | `{a.entity}` | "
                   f"{a.first:%d/%m %H:%M} → {a.last:%H:%M} | {_mitre(a)} |")
    for i, a in enumerate(alerts, 1):
        out += ["", f"## {i}. {a.title}", "",
                f"**Severidade:** {LABEL[a.severity]} · **Regra:** `{a.rule}` · "
                f"**Eventos:** {a.count}", "",
                f"**Ação recomendada (N1):** {a.action}", "", "```text"]
        out += [f"L{e.line_no}: {e.raw}" for e in a.evidence[:5]]
        out.append("```")
    return "\n".join(out) + "\n"


def render_json(alerts: list[Alert], stats: ParseStats) -> str:
    data = {
        "estatisticas": {"linhas": stats.lines, "eventos": stats.events,
                         "por_tipo": stats.by_kind},
        "alertas": [{
            "regra": a.rule, "titulo": a.title, "severidade": a.severity,
            "mitre": [{"id": t, "nome": n} for t, n in a.mitre],
            "origem": a.entity, "inicio": a.first.isoformat(), "fim": a.last.isoformat(),
            "eventos": a.count, "acao": a.action, **a.extra,
            "evidencia": [{"linha": e.line_no, "log": e.raw} for e in a.evidence],
        } for a in alerts],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)
