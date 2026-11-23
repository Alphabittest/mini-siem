import unittest

from minisiem import parser as p


def one(line, year=2026):
    events, _ = p.parse_lines([line], year=year)
    return events[0] if events else None


class ParserTest(unittest.TestCase):
    def test_ssh_falha_usuario_invalido(self):
        e = one("2026-11-20T03:14:10-03:00 srv sshd[1]: Failed password for invalid user "
                "admin from 203.0.113.45 port 51001 ssh2")
        self.assertEqual((e.kind, e.user, e.ip), (p.SSH_FAIL, "admin", "203.0.113.45"))

    def test_sshd_session_e_ipv6(self):
        e = one("2026-11-20T03:42:15-03:00 srv sshd-session[9]: Accepted publickey for ana "
                "from 2001:db8::7 port 4022 ssh2: ED25519 SHA256:x")
        self.assertEqual((e.kind, e.user, e.ip), (p.SSH_OK, "ana", "2001:db8::7"))

    def test_syslog_classico_usa_o_ano_informado(self):
        e = one("Nov 20 03:14:10 srv sshd[1]: Failed password for root from "
                "203.0.113.45 port 1 ssh2", year=2025)
        self.assertEqual((e.ts.year, e.ts.month, e.ts.hour), (2025, 11, 3))

    def test_falha_pam_do_sshd_nao_duplica(self):
        line = ("2026-11-20T03:14:10-03:00 srv sshd[1]: pam_unix(sshd:auth): authentication "
                "failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.45  user=root")
        self.assertIsNone(one(line))

    def test_falha_pam_local(self):
        e = one("2026-11-20T14:05:00-03:00 srv sudo[5]: pam_unix(sudo:auth): authentication "
                "failure; logname=ana uid=1000 euid=0 tty=/dev/pts/2 ruser=ana rhost=  user=ana")
        self.assertEqual((e.kind, e.service, e.user, e.ip), (p.AUTH_FAIL, "sudo", "ana", None))

    def test_sudo_exec_negado_e_nao_interativo(self):
        ok = one("2026-11-20T08:13:02-03:00 srv sudo[5]:  ana : TTY=pts/0 ; PWD=/home/ana ; "
                 "USER=root ; COMMAND=/usr/bin/id")
        neg = one("2026-11-20T08:13:02-03:00 srv sudo[5]:  ana : 3 incorrect password attempts"
                  " ; TTY=pts/0 ; PWD=/home/ana ; USER=root ; COMMAND=/usr/bin/id")
        n = one("2026-11-20T08:13:02-03:00 srv sudo[5]:  ana : a password is required ; "
                "PWD=/home/ana ; USER=root ; COMMAND=/usr/bin/true")
        self.assertEqual(ok.kind, p.SUDO_EXEC)
        self.assertEqual(neg.kind, p.SUDO_DENIED)
        self.assertIsNone(n)

    def test_usermod_conta_so_uma_vez(self):
        events, _ = p.parse_lines([
            "2026-11-20T03:43:45-03:00 srv usermod[1]: add 'x' to group 'wheel'",
            "2026-11-20T03:43:45-03:00 srv usermod[1]: add 'x' to shadow group 'wheel'"])
        self.assertEqual([(e.kind, e.detail) for e in events], [(p.GROUP_ADD, "wheel")])

    def test_linha_sem_interesse_e_lixo(self):
        events, stats = p.parse_lines(["2026-11-20T02:00:01-03:00 srv CROND[1]: (root) CMD (x)",
                                       "isso não é log", ""])
        self.assertEqual((events, stats.lines, stats.with_header), ([], 3, 1))


if __name__ == "__main__":
    unittest.main()
