"""Linha de comando: python -m minisiem ARQUIVO [opções]"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .parser import parse_lines
from .report import render_json, render_markdown, render_text
from .rules import SEVERITIES, Config, run_rules


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="minisiem",
        description="Detecta força bruta, password spraying, conta comprometida e "
                    "persistência em logs de autenticação Linux.",
        epilog="Exemplo: journalctl -o short-iso --since today | python -m minisiem -")
    ap.add_argument("arquivos", nargs="+",
                    help="auth.log, secure ou saída do journalctl -o short-iso ('-' = stdin)")
    ap.add_argument("-f", "--formato", choices=["texto", "markdown", "json"], default="texto")
    ap.add_argument("-o", "--saida", help="grava o resultado num arquivo em vez da tela")
    ap.add_argument("--janela", type=int, default=300,
                    help="segundos entre falhas para continuar o mesmo surto (padrão 300)")
    ap.add_argument("--limite", type=int, default=5,
                    help="falhas SSH num surto para virar força bruta (padrão 5)")
    ap.add_argument("--ano", type=int,
                    help="ano dos logs no formato syslog clássico, que não traz o ano")
    ap.add_argument("--severidade-min", choices=SEVERITIES, default="baixa",
                    help="esconde alertas abaixo desta severidade")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _read(paths: list[str]) -> list[str]:
    lines: list[str] = []
    for path in paths:
        if path == "-":
            lines += sys.stdin.readlines()
        else:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines += fh.readlines()
    return lines


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        lines = _read(args.arquivos)
    except OSError as exc:
        print(f"minisiem: não consegui ler o arquivo: {exc}", file=sys.stderr)
        return 2

    events, stats = parse_lines(lines, year=args.ano)
    cfg = Config(janela=args.janela, limite_ssh=args.limite)
    min_rank = SEVERITIES.index(args.severidade_min)
    alerts = [a for a in run_rules(events, cfg) if a.severity_rank >= min_rank]

    if args.formato == "json":
        out = render_json(alerts, stats)
    elif args.formato == "markdown":
        out = render_markdown(alerts, stats, source=", ".join(args.arquivos))
    else:
        out = render_text(alerts, stats, color=sys.stdout.isatty() and not args.saida)

    if args.saida:
        with open(args.saida, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Resultado gravado em {args.saida} ({len(alerts)} alerta(s)).")
    else:
        print(out)
    # Código de saída útil em cron/CI: 1 se houve alerta, 0 se não.
    return 1 if alerts else 0
