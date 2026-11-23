"""Regras de detecção. Cada regra recebe os eventos e devolve alertas.

Ideia central: um "surto" é uma sequência de falhas da mesma origem em que
entre uma falha e a próxima passam no máximo ``janela`` segundos.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import parser as p

SEVERITIES = ["baixa", "media", "alta", "critica"]
PRIVILEGED_GROUPS = {"wheel", "sudo", "admin", "root", "adm", "docker", "lxd"}


@dataclass
class Config:
    janela: int = 300          # segundos entre falhas para continuar o mesmo surto
    limite_ssh: int = 5        # falhas SSH num surto para virar força bruta
    usuarios_spray: int = 3    # usuários distintos para considerar password spraying
    limite_local: int = 3      # falhas locais (sudo, su, tela de bloqueio) num surto
    retrospectiva: int = 3600  # segundos olhados para trás antes de um login com sucesso


@dataclass
class Alert:
    rule: str
    title: str
    severity: str
    mitre: list[tuple[str, str]]
    entity: str
    first: datetime
    last: datetime
    count: int
    evidence: list[p.Event]
    action: str
    extra: dict = field(default_factory=dict)

    @property
    def severity_rank(self) -> int:
        return SEVERITIES.index(self.severity)


def _bursts(events: list[p.Event], gap: int) -> list[list[p.Event]]:
    out: list[list[p.Event]] = []
    for e in events:
        if out and (e.ts - out[-1][-1].ts).total_seconds() <= gap:
            out[-1].append(e)
        else:
            out.append([e])
    return out


def _group(events, kind, key):
    groups = defaultdict(list)
    for e in events:
        if e.kind == kind:
            groups[key(e)].append(e)
    return groups


def ssh_bursts(events: list[p.Event], cfg: Config) -> list[Alert]:
    """Classifica cada surto de falhas SSH de um IP: spraying ou força bruta."""
    alerts = []
    for ip, fails in _group(events, p.SSH_FAIL, lambda e: e.ip).items():
        for burst in _bursts(fails, cfg.janela):
            users = sorted({e.user for e in burst})
            per_user = len(burst) / len(users)
            common = dict(entity=ip, first=burst[0].ts, last=burst[-1].ts,
                          count=len(burst), evidence=burst, extra={"usuarios": users})
            if len(users) >= cfg.usuarios_spray and per_user <= 2:
                alerts.append(Alert(
                    rule="SSH-SPRAY", severity="media",
                    title=f"Password spraying via SSH: {len(users)} usuários testados",
                    mitre=[("T1110.003", "Brute Force: Password Spraying")],
                    action="Conferir se os usuários testados existem no servidor e se algum "
                           "tem senha fraca. Bloquear o IP (firewall/fail2ban).",
                    **common))
            elif len(burst) >= cfg.limite_ssh:
                alerts.append(Alert(
                    rule="SSH-BRUTE", severity="media",
                    title=f"Força bruta via SSH: {len(burst)} falhas em "
                          f"{_dur(burst[0].ts, burst[-1].ts)}",
                    mitre=[("T1110.001", "Brute Force: Password Guessing")],
                    action="Verificar se algum login desse IP deu certo depois (regra "
                           "SSH-COMPROMISE). Bloquear o IP e avaliar desligar login por senha.",
                    **common))
    return alerts


def ssh_compromise(events: list[p.Event], cfg: Config) -> list[Alert]:
    """Login com sucesso vindo de um IP que acabou de errar várias vezes."""
    alerts = []
    fails_by_ip = _group(events, p.SSH_FAIL, lambda e: e.ip)
    for ok in (e for e in events if e.kind == p.SSH_OK):
        start = ok.ts - timedelta(seconds=cfg.retrospectiva)
        before = [f for f in fails_by_ip.get(ok.ip, []) if start <= f.ts <= ok.ts]
        if len(before) >= cfg.limite_ssh:
            alerts.append(Alert(
                rule="SSH-COMPROMISE", severity="critica",
                title=f"Login com sucesso como '{ok.user}' depois de {len(before)} falhas",
                mitre=[("T1110", "Brute Force"), ("T1078", "Valid Accounts")],
                entity=f"{ok.ip} -> {ok.user}", first=before[0].ts, last=ok.ts,
                count=len(before) + 1, evidence=before[-3:] + [ok],
                action="Escalar para o N2 agora: tratar a conta como comprometida. Encerrar "
                       "as sessões, trocar a senha e revisar o que foi feito depois do login.",
                extra={"usuario": ok.user}))
    return alerts


def local_auth(events: list[p.Event], cfg: Config) -> list[Alert]:
    """Várias senhas erradas no sudo, su, tela de bloqueio etc."""
    alerts = []
    groups = _group(events, p.AUTH_FAIL, lambda e: (e.service, e.user))
    for (service, user), fails in groups.items():
        for burst in _bursts(fails, cfg.janela):
            if len(burst) < cfg.limite_local:
                continue
            alerts.append(Alert(
                rule="LOCAL-AUTH", severity="baixa",
                title=f"{len(burst)} senhas erradas em '{service}' para '{user}'",
                mitre=[("T1110.001", "Brute Force: Password Guessing")],
                entity=f"{user}@{service}", first=burst[0].ts, last=burst[-1].ts,
                count=len(burst), evidence=burst,
                action="Confirmar com o dono da conta se foi ele errando a senha (o mais "
                       "comum). Se não foi, investigar quem tinha acesso à sessão/máquina."))
    return alerts


def new_user(events: list[p.Event], cfg: Config) -> list[Alert]:
    return [Alert(
        rule="NEW-USER", severity="media",
        title=f"Usuário local criado: '{e.user}' ({e.detail})",
        mitre=[("T1136.001", "Create Account: Local Account")],
        entity=e.user, first=e.ts, last=e.ts, count=1, evidence=[e],
        action="Confirmar se a criação foi autorizada (chamado de mudança). Conta criada "
               "logo depois de um login suspeito é sinal de persistência.")
        for e in events if e.kind == p.USER_CREATED]


def privileged_group(events: list[p.Event], cfg: Config) -> list[Alert]:
    return [Alert(
        rule="PRIV-GROUP", severity="alta",
        title=f"'{e.user}' adicionado ao grupo privilegiado '{e.detail}'",
        mitre=[("T1098", "Account Manipulation")],
        entity=e.user, first=e.ts, last=e.ts, count=1, evidence=[e],
        action="Confirmar a autorização. Se não houver, é escalada de privilégio: escalar "
               "para o N2 e remover a conta do grupo.")
        for e in events if e.kind == p.GROUP_ADD and e.detail in PRIVILEGED_GROUPS]


RULES = [ssh_compromise, ssh_bursts, privileged_group, new_user, local_auth]


def run_rules(events: list[p.Event], cfg: Config | None = None) -> list[Alert]:
    cfg = cfg or Config()
    alerts = [a for rule in RULES for a in rule(events, cfg)]
    alerts.sort(key=lambda a: (-a.severity_rank, a.first))
    return alerts


def _dur(a: datetime, b: datetime) -> str:
    s = int((b - a).total_seconds())
    return f"{s}s" if s < 60 else f"{s // 60}min{s % 60:02d}s"
