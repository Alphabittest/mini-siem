import unittest
from pathlib import Path

from minisiem.parser import parse_lines
from minisiem.rules import Config, run_rules

SAMPLE = Path(__file__).parent.parent / "samples" / "auth-ataque.log"


def fails(ip, users, start_s=0, step=10):
    return [f"2026-11-20T03:{(start_s + i * step) // 60:02d}:{(start_s + i * step) % 60:02d}"
            f"-03:00 srv sshd[1]: Failed password for {u} from {ip} port 1 ssh2"
            for i, u in enumerate(users)]


def rules_for(lines, **cfg):
    events, _ = parse_lines(lines, year=2026)
    return [a.rule for a in run_rules(events, Config(**cfg))]


class RulesTest(unittest.TestCase):
    def test_amostra_gera_os_seis_alertas_em_ordem_de_severidade(self):
        events, _ = parse_lines(SAMPLE.read_text().splitlines())
        self.assertEqual([a.rule for a in run_rules(events)],
                         ["SSH-COMPROMISE", "PRIV-GROUP", "SSH-SPRAY", "SSH-BRUTE",
                          "NEW-USER", "LOCAL-AUTH"])

    def test_forca_bruta_respeita_o_limite(self):
        self.assertEqual(rules_for(fails("198.51.100.1", ["deploy"] * 4)), [])
        self.assertEqual(rules_for(fails("198.51.100.1", ["deploy"] * 5)), ["SSH-BRUTE"])

    def test_pausa_maior_que_a_janela_separa_os_surtos(self):
        # 4 falhas, pausa de 10 min, mais 4: nenhum surto chega a 5
        lines = fails("198.51.100.1", ["d"] * 4) + fails("198.51.100.1", ["d"] * 4, start_s=700)
        self.assertEqual(rules_for(lines), [])
        self.assertEqual(rules_for(lines, janela=900), ["SSH-BRUTE"])

    def test_spray_muitos_usuarios_poucas_tentativas(self):
        users = ["root", "admin", "oracle", "test"]
        self.assertEqual(rules_for(fails("203.0.113.9", users)), ["SSH-SPRAY"])

    def test_sucesso_sem_falhas_antes_nao_alerta(self):
        ok = ("2026-11-20T08:12:44-03:00 srv sshd[1]: Accepted publickey for ana from "
              "192.0.2.10 port 5 ssh2")
        self.assertEqual(rules_for([ok]), [])

    def test_ips_diferentes_nao_se_somam(self):
        lines = [l for i in range(5) for l in fails(f"198.51.100.{i}", ["d"], start_s=i)]
        self.assertEqual(rules_for(lines), [])

    def test_grupo_comum_nao_alerta(self):
        line = "2026-11-20T03:43:45-03:00 srv usermod[1]: add 'ana' to group 'video'"
        self.assertEqual(rules_for([line]), [])


if __name__ == "__main__":
    unittest.main()
