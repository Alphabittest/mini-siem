import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from minisiem.cli import main

SAMPLE = str(Path(__file__).parent.parent / "samples" / "auth-ataque.log")


def run(*args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class CliTest(unittest.TestCase):
    def test_json_e_codigo_de_saida(self):
        code, out = run(SAMPLE, "-f", "json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(len(data["alertas"]), 6)
        self.assertEqual(data["alertas"][0]["usuario"], "deploy")

    def test_severidade_minima_filtra(self):
        _, out = run(SAMPLE, "-f", "json", "--severidade-min", "alta")
        self.assertEqual([a["regra"] for a in json.loads(out)["alertas"]],
                         ["SSH-COMPROMISE", "PRIV-GROUP"])

    def test_markdown_tem_tabela(self):
        _, out = run(SAMPLE, "-f", "markdown")
        self.assertIn("| 1 | CRÍTICA | SSH-COMPROMISE |", out)

    def test_arquivo_inexistente_devolve_2(self):
        self.assertEqual(main(["nao-existe.log"]), 2)


if __name__ == "__main__":
    unittest.main()
