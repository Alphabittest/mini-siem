# Relatório de triagem: mini-siem

- **Fonte:** `samples/auth-ataque.log`
- **Linhas lidas:** 39 · **eventos de autenticação:** 30
- **Alertas:** 6 (CRÍTICA 1 · ALTA 1 · MÉDIA 3 · BAIXA 1)

| # | Severidade | Regra | Origem | Período | MITRE ATT&CK |
|---|---|---|---|---|---|
| 1 | CRÍTICA | SSH-COMPROMISE | `198.51.100.23 -> deploy` | 20/11 03:40 → 03:42 | T1110 Brute Force, T1078 Valid Accounts |
| 2 | ALTA | PRIV-GROUP | `suporte` | 20/11 03:43 → 03:43 | T1098 Account Manipulation |
| 3 | MÉDIA | SSH-SPRAY | `203.0.113.45` | 20/11 03:14 → 03:14 | T1110.003 Brute Force: Password Spraying |
| 4 | MÉDIA | SSH-BRUTE | `198.51.100.23` | 20/11 03:40 → 03:41 | T1110.001 Brute Force: Password Guessing |
| 5 | MÉDIA | NEW-USER | `suporte` | 20/11 03:43 → 03:43 | T1136.001 Create Account: Local Account |
| 6 | BAIXA | LOCAL-AUTH | `ana@sudo` | 20/11 14:05 → 14:05 | T1110.001 Brute Force: Password Guessing |

## 1. Login com sucesso como 'deploy' depois de 8 falhas

**Severidade:** CRÍTICA · **Regra:** `SSH-COMPROMISE` · **Eventos:** 9

**Ação recomendada (N1):** Escalar para o N2 agora: tratar a conta como comprometida. Encerrar as sessões, trocar a senha e revisar o que foi feito depois do login.

```text
L22: 2026-11-20T03:41:25-03:00 srv-web01 sshd-session[4305]: Failed password for deploy from 198.51.100.23 port 40105 ssh2
L23: 2026-11-20T03:41:40-03:00 srv-web01 sshd-session[4306]: Failed password for deploy from 198.51.100.23 port 40106 ssh2
L24: 2026-11-20T03:41:55-03:00 srv-web01 sshd-session[4307]: Failed password for deploy from 198.51.100.23 port 40107 ssh2
L25: 2026-11-20T03:42:15-03:00 srv-web01 sshd-session[4310]: Accepted password for deploy from 198.51.100.23 port 40110 ssh2
```

## 2. 'suporte' adicionado ao grupo privilegiado 'wheel'

**Severidade:** ALTA · **Regra:** `PRIV-GROUP` · **Eventos:** 1

**Ação recomendada (N1):** Confirmar a autorização. Se não houver, é escalada de privilégio: escalar para o N2 e remover a conta do grupo.

```text
L30: 2026-11-20T03:43:45-03:00 srv-web01 usermod[4324]: add 'suporte' to group 'wheel'
```

## 3. Password spraying via SSH: 6 usuários testados

**Severidade:** MÉDIA · **Regra:** `SSH-SPRAY` · **Eventos:** 8

**Ação recomendada (N1):** Conferir se os usuários testados existem no servidor e se algum tem senha fraca. Bloquear o IP (firewall/fail2ban).

```text
L3: 2026-11-20T03:14:03-03:00 srv-web01 sshd[4100]: Failed password for root from 203.0.113.45 port 51000 ssh2
L5: 2026-11-20T03:14:10-03:00 srv-web01 sshd[4101]: Failed password for invalid user admin from 203.0.113.45 port 51001 ssh2
L7: 2026-11-20T03:14:17-03:00 srv-web01 sshd[4102]: Failed password for invalid user oracle from 203.0.113.45 port 51002 ssh2
L9: 2026-11-20T03:14:24-03:00 srv-web01 sshd[4103]: Failed password for invalid user postgres from 203.0.113.45 port 51003 ssh2
L11: 2026-11-20T03:14:31-03:00 srv-web01 sshd[4104]: Failed password for invalid user test from 203.0.113.45 port 51004 ssh2
```

## 4. Força bruta via SSH: 8 falhas em 1min45s

**Severidade:** MÉDIA · **Regra:** `SSH-BRUTE` · **Eventos:** 8

**Ação recomendada (N1):** Verificar se algum login desse IP deu certo depois (regra SSH-COMPROMISE). Bloquear o IP e avaliar desligar login por senha.

```text
L17: 2026-11-20T03:40:10-03:00 srv-web01 sshd-session[4300]: Failed password for deploy from 198.51.100.23 port 40100 ssh2
L18: 2026-11-20T03:40:25-03:00 srv-web01 sshd-session[4301]: Failed password for deploy from 198.51.100.23 port 40101 ssh2
L19: 2026-11-20T03:40:40-03:00 srv-web01 sshd-session[4302]: Failed password for deploy from 198.51.100.23 port 40102 ssh2
L20: 2026-11-20T03:40:55-03:00 srv-web01 sshd-session[4303]: Failed password for deploy from 198.51.100.23 port 40103 ssh2
L21: 2026-11-20T03:41:10-03:00 srv-web01 sshd-session[4304]: Failed password for deploy from 198.51.100.23 port 40104 ssh2
```

## 5. Usuário local criado: 'suporte' (UID=1002)

**Severidade:** MÉDIA · **Regra:** `NEW-USER` · **Eventos:** 1

**Ação recomendada (N1):** Confirmar se a criação foi autorizada (chamado de mudança). Conta criada logo depois de um login suspeito é sinal de persistência.

```text
L28: 2026-11-20T03:43:30-03:00 srv-web01 useradd[4322]: new user: name=suporte, UID=1002, GID=1002, home=/home/suporte, shell=/bin/bash, from=/dev/pts/1
```

## 6. 3 senhas erradas em 'sudo' para 'ana'

**Severidade:** BAIXA · **Regra:** `LOCAL-AUTH` · **Eventos:** 3

**Ação recomendada (N1):** Confirmar com o dono da conta se foi ele errando a senha (o mais comum). Se não foi, investigar quem tinha acesso à sessão/máquina.

```text
L36: 2026-11-20T14:05:00-03:00 srv-web01 sudo[5100]: pam_unix(sudo:auth): authentication failure; logname=ana uid=1000 euid=0 tty=/dev/pts/2 ruser=ana rhost=  user=ana
L37: 2026-11-20T14:05:12-03:00 srv-web01 sudo[5100]: pam_unix(sudo:auth): authentication failure; logname=ana uid=1000 euid=0 tty=/dev/pts/2 ruser=ana rhost=  user=ana
L38: 2026-11-20T14:05:24-03:00 srv-web01 sudo[5100]: pam_unix(sudo:auth): authentication failure; logname=ana uid=1000 euid=0 tty=/dev/pts/2 ruser=ana rhost=  user=ana
```
