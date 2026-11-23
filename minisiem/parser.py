"""Leitura de logs de autenticação (syslog clássico ou journalctl -o short-iso).

Cada linha reconhecida vira um ``Event`` normalizado. Linhas que não interessam
(cron, kernel etc.) são só contadas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

# Tipos de evento
SSH_FAIL = "ssh_falha"
SSH_OK = "ssh_sucesso"
AUTH_FAIL = "auth_falha_local"
SUDO_EXEC = "sudo_exec"
SUDO_DENIED = "sudo_negado"
USER_CREATED = "usuario_criado"
GROUP_ADD = "usuario_em_grupo"

# Cabeçalho do journalctl -o short-iso: 2026-11-20T03:41:12-03:00 host prog[pid]: msg
ISO_HEADER = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)
# Cabeçalho do syslog clássico (/var/log/auth.log): Nov 20 03:41:12 host prog[pid]: msg
SYSLOG_HEADER = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[\d+\])?:\s?(?P<msg>.*)$"
)
MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}

IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
RE_SSH_FAIL = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S*) from " + IP + r" port \d+")
RE_SSH_OK = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from " + IP + r" port \d+")
RE_PAM_FAIL = re.compile(
    r"^pam_unix\((?P<service>[^:)]+):auth\): authentication failure;"
    r".*\brhost=(?P<rhost>\S*)(?:\s+user=(?P<user>\S+))?")
RE_SUDO = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<pre>[^;]*?) ; )?(?:TTY=\S+ ; )?PWD=.*? ; "
    r"USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
RE_USERADD = re.compile(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)")
# O usermod registra a mesma adição duas vezes ("group" e "shadow group"): só a 1ª conta.
RE_USERMOD = re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
RE_GPASSWD = re.compile(r"^user (?P<user>\S+) added by \S+ to group (?P<group>\S+)")


@dataclass
class Event:
    line_no: int
    ts: datetime
    host: str
    program: str
    kind: str
    raw: str
    user: str | None = None
    ip: str | None = None
    service: str | None = None
    detail: str | None = None


@dataclass
class ParseStats:
    lines: int = 0
    with_header: int = 0
    events: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)


def _parse_header(line: str, year: int):
    m = ISO_HEADER.match(line)
    if m:
        ts = datetime.fromisoformat(m["ts"])
        # Guarda a hora local do log: dentro de um mesmo arquivo o fuso é o mesmo.
        return ts.replace(tzinfo=None), m["host"], m["prog"], m["msg"]
    m = SYSLOG_HEADER.match(line)
    if m and m["mon"] in MONTHS:
        h, mi, s = (int(x) for x in m["time"].split(":"))
        ts = datetime(year, MONTHS[m["mon"]], int(m["day"]), h, mi, s)
        return ts, m["host"], m["prog"], m["msg"]
    return None


def _classify(prog: str, msg: str) -> dict | None:
    """Devolve os campos do evento ou None se a mensagem não interessa."""
    if prog.startswith("sshd"):  # sshd e sshd-session (OpenSSH >= 9.8)
        if m := RE_SSH_FAIL.match(msg):
            return dict(kind=SSH_FAIL, user=m["user"] or "?", ip=m["ip"], detail=m["method"])
        if m := RE_SSH_OK.match(msg):
            return dict(kind=SSH_OK, user=m["user"], ip=m["ip"], detail=m["method"])
        return None  # a falha PAM do sshd duplicaria o "Failed password"
    if m := RE_PAM_FAIL.match(msg):
        return dict(kind=AUTH_FAIL, user=m["user"] or "?", ip=m["rhost"] or None,
                    service=m["service"])
    if prog == "sudo" and (m := RE_SUDO.match(msg)):
        pre = m["pre"] or ""
        if "incorrect password" in pre:
            return dict(kind=SUDO_DENIED, user=m["user"], detail=m["cmd"])
        if "password is required" in pre:  # sudo -n sem senha em cache: não é ataque
            return None
        return dict(kind=SUDO_EXEC, user=m["user"], detail=f"{m['target']}: {m['cmd']}")
    if prog == "useradd" and (m := RE_USERADD.match(msg)):
        return dict(kind=USER_CREATED, user=m["user"].strip(), detail=f"UID={m['uid']}")
    if prog == "usermod" and (m := RE_USERMOD.match(msg)):
        return dict(kind=GROUP_ADD, user=m["user"], detail=m["group"])
    if prog == "gpasswd" and (m := RE_GPASSWD.match(msg)):
        return dict(kind=GROUP_ADD, user=m["user"], detail=m["group"])
    return None


def parse_lines(lines, year: int | None = None) -> tuple[list[Event], ParseStats]:
    """Lê linhas de log e devolve os eventos em ordem de horário."""
    year = year or datetime.now().year
    stats = ParseStats()
    events: list[Event] = []
    for n, line in enumerate(lines, start=1):
        line = line.rstrip("\r\n")
        stats.lines += 1
        header = _parse_header(line, year)
        if not header:
            continue
        stats.with_header += 1
        ts, host, prog, msg = header
        fields = _classify(prog, msg)
        if not fields:
            continue
        events.append(Event(line_no=n, ts=ts, host=host, program=prog, raw=line, **fields))
        stats.by_kind[fields["kind"]] = stats.by_kind.get(fields["kind"], 0) + 1
    stats.events = len(events)
    events.sort(key=lambda e: (e.ts, e.line_no))
    return events, stats
