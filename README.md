# mini-siem

Detector de ataques de autenticação em logs Linux, feito para treinar o trabalho de
um analista de SOC N1: **ler o log, separar o que é ataque do que é ruído, mapear no
MITRE ATT&CK e dizer qual é a próxima ação.**

Ele lê o `auth.log`/`secure` ou a saída do `journalctl` e encontra força bruta,
password spraying, conta comprometida, criação de usuário e escalada de privilégio.
Não substitui um SIEM de verdade (Wazuh, Splunk, Sentinel): é uma versão pequena,
legível e testada da lógica de correlação que eles fazem.

**Só biblioteca padrão do Python (3.11+).** Não precisa de `pip install`.

## O que ele detecta

| Regra | O que procura | Severidade | MITRE ATT&CK |
|---|---|---|---|
| `SSH-COMPROMISE` | login SSH **com sucesso** vindo de um IP que errou a senha 5+ vezes na última hora | Crítica | T1110 Brute Force · T1078 Valid Accounts |
| `PRIV-GROUP` | usuário adicionado a `wheel`, `sudo`, `admin`, `docker`… | Alta | T1098 Account Manipulation |
| `SSH-SPRAY` | um IP testando 3+ usuários diferentes, com poucas senhas por usuário | Média | T1110.003 Password Spraying |
| `SSH-BRUTE` | um IP errando a senha 5+ vezes seguidas | Média | T1110.001 Password Guessing |
| `NEW-USER` | conta local criada (`useradd`) | Média | T1136.001 Create Account: Local Account |
| `LOCAL-AUTH` | 3+ senhas erradas no `sudo`, `su`, tela de login ou de bloqueio | Baixa | T1110.001 Password Guessing |

Cada alerta traz a **origem**, o **período**, as **linhas do log que provam** o alerta
e a **ação recomendada para o N1** (bloquear, confirmar com o usuário ou escalar para o N2).

## Rodar

```bash
# o exemplo do repositório (um ataque encenado, do primeiro teste até a persistência)
python -m minisiem samples/auth-ataque.log

# o log da sua máquina (systemd)
journalctl -o short-iso --since "7 days ago" | python -m minisiem -

# Debian/Ubuntu com rsyslog (o formato clássico não traz o ano)
sudo python -m minisiem /var/log/auth.log --ano 2026

# relatório em Markdown ou JSON, só do que for alta ou crítica
python -m minisiem samples/auth-ataque.log -f markdown -o relatorio.md
python -m minisiem samples/auth-ataque.log -f json --severidade-min alta
```

O código de saída é **1 quando há alerta** e **0 quando não há**, então dá pra usar em
`cron` ou num pipeline. `--janela` e `--limite` ajustam a sensibilidade (`--help` mostra tudo).

## O ataque do exemplo

O `samples/auth-ataque.log` conta uma madrugada num servidor web (todos os IPs são
das faixas reservadas para documentação, RFC 5737):

1. **03:14**: `203.0.113.45` testa `root`, `admin`, `oracle`, `postgres`… uma ou duas senhas cada → **SSH-SPRAY**
2. **03:40**: `198.51.100.23` erra a senha da conta `deploy` 8 vezes em 1min45s → **SSH-BRUTE**
3. **03:42**: o mesmo IP **acerta** a senha → **SSH-COMPROMISE** (crítico)
4. **03:43**: já dentro, o invasor lê o `/etc/shadow`, cria o usuário `suporte` → **NEW-USER**
   e coloca ele no grupo `wheel` → **PRIV-GROUP**
5. **14:05**: a administradora `ana` erra a senha do `sudo` 3 vezes → **LOCAL-AUTH**, que é o
   **falso positivo** do dia. O erro único das 09:01 não gera alerta.

Saída (resumida):

```text
39 linhas lidas, 30 eventos de autenticação, 6 alerta(s)  [CRÍTICA 1 · ALTA 1 · MÉDIA 3 · BAIXA 1]

1. [CRÍTICA] SSH-COMPROMISE: Login com sucesso como 'deploy' depois de 8 falhas
   Origem:   198.51.100.23 -> deploy
   Período:  20/11 03:40:10 → 20/11 03:42:15  (9 evento(s))
   MITRE:    T1110 Brute Force, T1078 Valid Accounts
   Ação N1:  Escalar para o N2 agora: tratar a conta como comprometida. Encerrar as
             sessões, trocar a senha e revisar o que foi feito depois do login.
   Evidência:
     L24: ... Failed password for deploy from 198.51.100.23 port 40107 ssh2
     L25: ... Accepted password for deploy from 198.51.100.23 port 40110 ssh2
...
```

O relatório completo em Markdown está em [`samples/exemplo-relatorio.md`](samples/exemplo-relatorio.md).

## Como as regras decidem

- **Surto:** falhas da mesma origem em que entre uma e a próxima passam no máximo
  `--janela` segundos (padrão 300). Se o atacante pausa mais que isso, começa um surto novo.
  É simples de explicar e de ajustar, e pega tanto ataque rápido quanto "devagar e sempre"
  dentro da janela.
- **Spraying × força bruta:** o mesmo surto é classificado uma vez só. Muitos usuários
  com até 2 tentativas por usuário é spraying. Muitas tentativas é força bruta. Assim o
  mesmo ataque não vira dois alertas.
- **Sem contagem dupla:** o `sshd` registra cada senha errada duas vezes (`Failed password` e
  a falha do PAM), e o `usermod` registra a adição ao grupo duas vezes (`group` e
  `shadow group`). Só uma conta.
- **`sudo -n`** sem senha em cache ("a password is required") é ignorado: é script, não ataque.
- Aceita `sshd` e `sshd-session` (o nome novo a partir do OpenSSH 9.8) e IPv6.

## Testado no meu próprio Arch

Rodei no `journalctl` da minha máquina desde setembro: **~509 mil linhas em menos de 1
segundo**, com 3 alertas de severidade baixa (`LOCAL-AUTH`): senha errada na tela de login,
na tela de bloqueio e 6 tentativas de `su -` para root.

Do `su` eu não lembrava, então fiz a triagem como um N1 faria, voltando ao log em volta do alerta:

- as 6 falhas vieram do **meu usuário**, no **terminal local `pts/4`**, sem `rhost` (não é acesso remoto);
- foram todas em ~1 minuto e pararam sozinhas;
- **36 segundos depois**, no mesmo `pts/4`, o meu usuário rodou `sudo pacman -S ...` com sucesso.

Conclusão: eu tentei virar root com `su -`, não consegui e usei o `sudo`. **Falso positivo,
fechado.** É por isso que essa regra é **baixa**: o mais comum é o próprio dono da conta.
Os logs reais não estão no repositório.

## Limitações

- Analisa o arquivo depois do fato, não em tempo real.
- Não tem GeoIP, lista de reputação de IP nem allowlist de IPs da empresa.
- Só Linux. No Windows o equivalente seriam os eventos 4625/4624/4720/4732.
- Os limites são fixos por regra, não aprendidos a partir do comportamento normal.

## Estrutura

```text
minisiem/
  parser.py   lê syslog clássico ou journalctl e normaliza os eventos
  rules.py    as 6 regras de detecção e o mapeamento MITRE
  report.py   saída em texto, Markdown ou JSON
  cli.py      linha de comando
samples/      o ataque encenado e o relatório gerado
tests/        19 testes (python -m unittest)
```

## Testes

```bash
python -m unittest -v
```

## Autor

**Ygor Andrade Silman**, estudante de Segurança Cibernética na FIAP.
[LinkedIn](https://www.linkedin.com/in/ygor-silman/) · [GitHub](https://github.com/Alphabittest)
