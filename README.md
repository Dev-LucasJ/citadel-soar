# 🛡️ CITADEL

```
 ██████╗██╗████████╗ █████╗ ██████╗ ███████╗██╗
██╔════╝██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║
██║     ██║   ██║   ███████║██║  ██║█████╗  ██║
██║     ██║   ██║   ██╔══██║██║  ██║██╔══╝  ██║
╚██████╗██║   ██║   ██║  ██║██████╔╝███████╗███████╗
 ╚═════╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝

  Mini-SOAR headless para defesa ativa de servidores Linux
  "O servidor que bloqueia seus próprios atacantes."
```

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Purpose](https://img.shields.io/badge/Purpose-Educational%20%2F%20Lab-orange?style=flat-square)
![Team](https://img.shields.io/badge/Blue%20Team-Active%20Defense-blue?style=flat-square)

---

## 📖 Origem do Projeto

Durante sessões de lab na **HackTheBox**, surgiu uma pergunta prática:

> *E se eu automatizasse o lado azul enquanto faço o pentest?*

Ficar alternando entre terminal de ataque e leitura manual de logs gigantes do `sshd` quebrava o ritmo das sessões. O **Citadel** nasceu como solução: um operador Blue Team autônomo que fica de vigia enquanto você faz o pentest, detecta brute-force em tempo real e bloqueia o atacante antes que ele encontre a senha certa.

O projeto virou também um exercício de **Purple Team** na prática — você é forçado a pensar como Red (qual wordlist, quantas threads, qual vetor) e como Blue (qual é a assinatura do ataque no log, em quanto tempo o defensor reage) ao mesmo tempo.

---

## ⚙️ O que o Citadel faz

```
┌─────────────────────────────────────────────────────────────┐
│                      FLUXO DE OPERAÇÃO                      │
└─────────────────────────────────────────────────────────────┘

  journald / journalctl
        │
        │  (leitura em tempo real, non-blocking)
        ▼
  ┌─────────────┐
  │  citadel.py │  ◄── orquestrador principal
  │             │
  │  Pré-filtro │  "Failed password" in message?  ──► NÃO → descarta
  │  Regex      │  extrai IP + Usuário
  └──────┬──────┘
         │
         ▼
  ┌──────────────────┐
  │  containment.py  │  ◄── motor de decisão
  │                  │
  │  is_whitelisted? │  ──► SIM → ignora evento
  │  já bloqueado?   │  ──► SIM → ignora evento
  │  ThreatMemory    │  sliding window (deque O(1))
  │  .record(ip)     │
  └──────┬───────────┘
         │
         │  atingiu MAX_FAILURES em TIME_WINDOW?
         │
    NÃO ─┤─ SIM
         │    │
         │    ▼
         │  block_ip(ip)
         │    ├── _block_via_blackhole()  ◄── PRIMÁRIO
         │    │     ip route add blackhole <ip>/32
         │    │     (descarte no kernel, abaixo do netfilter)
         │    │
         │    └── _block_via_iptables()  ◄── FALLBACK
         │          iptables -I INPUT -s <ip> -j DROP
         │
         ▼
    [ALERTA] log formatado no terminal
```

---

## 🗂️ Estrutura do Repositório

```
citadel/
├── citadel.py          # Orquestrador: leitura de logs + loop principal
├── citadel_bypass.py   # Variante sem systemd-python (journalctl via subprocess)
├── containment.py      # Motor de contenção: whitelist, memória, bloqueio
└── README.md
```

---

## 🧠 Arquitetura em 3 Fases

### Fase 1 — Leitura em Tempo Real

O Citadel se conecta diretamente ao **journald** (sistema de logs do systemd) usando a biblioteca `systemd-python`, ou via `journalctl` subprocess no modo bypass.

**Por que não `tail -f /var/log/auth.log`?**
- `journald` é a fonte primária; `auth.log` é uma saída derivada e pode ter delay
- A API do journald permite filtrar por `_SYSTEMD_UNIT` antes de ler — reduz o volume de dados no pipe
- `j.wait(1.0)` bloqueia por no máximo 1 segundo e retorna quando há novos eventos: **CPU = 0%** em idle

```python
# Non-blocking com timeout — imune a Ctrl+C surdo
event = j.wait(1.0)
if event == journal.NOP:
    continue  # timeout, nenhum evento novo
```

---

### Fase 2 — Extração Cirúrgica com Regex

```python
_SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>[\w\.\-]+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
```

**Decisões de design:**

| Decisão | Motivo |
|---|---|
| Grupos **nomeados** `(?P<name>...)` | Imunes a refactoring — `group("ip")` não quebra se você adicionar grupos antes |
| Pré-filtro `"Failed password" in message` | Busca de substring em C — descarta 99% das mensagens antes do Regex |
| Regex **pré-compilado** no módulo | Compilado uma vez na carga; não recompila a cada chamada |

Cobre dois padrões do sshd:
```
Failed password for root from 192.168.1.10 port 54321 ssh2
Failed password for invalid user admin from 10.0.0.5 port 22 ssh2
```

---

### Fase 3 — Motor de Resposta (O "R" do SOAR)

#### 3.1 Whitelist com CIDRs

```python
WHITELIST_RAW = [
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",
    # Adicione seu IP de gestão aqui
]
```

Convertido para objetos `ipaddress.ip_network` **uma vez** na carga do módulo. A checagem no loop é só `addr in network` — sem parsing repetido.

#### 3.2 Memória de Curto Prazo — Sliding Window

```
Estrutura: dict[str, deque[float]]
  IP      →  timestamps das falhas
```

```
Exemplo (TIME_WINDOW=60s, now=T):

  Evento entra → expurga timestamps antigos → adiciona novo → conta

  t=0s:   deque = [0.0]           → 1 falha
  t=15s:  deque = [0.0, 15.0]     → 2 falhas
  t=30s:  deque = [0.0, 15.0, 30.0, 45.0, 60.0] → 5 falhas → BLOQUEIO
  t=61s:  deque = [15.0, 30.0, 45.0, 60.0, 61.0] → t=0 expirou → ainda 5
  t=76s:  deque = [30.0, 45.0, 60.0, 61.0, 76.0] → t=15 expirou → ainda 5
```

**Por que `deque(maxlen=N)` e não `list`?**
- `append()` em deque cheia descarta o mais antigo em **O(1)** automaticamente
- `list` exigiria `lista = lista[-N:]` — cria novo objeto a cada evento
- Em um ataque de 10k req/min, a diferença é mensurável

**Por que `time.monotonic()` e não `time.time()`?**
- `time.time()` pode *voltar no tempo* (ajuste NTP, horário de verão)
- Se o relógio recuar durante um ataque, timestamps "dentro da janela" seriam considerados expirados — o atacante escaparia do limiar
- `monotonic()` é garantidamente crescente

**Expurgo de RAM amortizado:**
```python
# Custo O(n) a cada 50 eventos = custo médio O(1) por evento
self._events_since_purge += 1
if self._events_since_purge >= 50:
    self._purge_stale_ips(now)
    self._events_since_purge = 0
```
Sem isso, IPs que pararam de atacar ficam em memória para sempre.

#### 3.3 Mecanismo de Bloqueio Duplo

```
block_ip(ip)
  │
  ├─► _block_via_blackhole()   [PRIMÁRIO]
  │     ip route add blackhole <ip>/32
  │     • Descarte no kernel, ANTES do netfilter
  │     • Mais eficiente que iptables
  │     • Presente em qualquer Linux com iproute2
  │     • Idempotente: EEXIST → sucesso silencioso
  │
  └─► _block_via_iptables()    [FALLBACK automático]
        iptables -I INPUT -s <ip> -j DROP
        • -I insere no TOPO da chain (precedência garantida)
        • Fallback se iproute2 indisponível
```

**Blackhole vs iptables DROP:**

| | `ip route blackhole` | `iptables -j DROP` |
|---|---|---|
| Camada | Roteamento (L3) | Netfilter (L3/L4) |
| Eficiência | ✅ Mais rápido | Razoável |
| Disponibilidade | ✅ iproute2 universal | Requer módulo carregado |
| Feedback ao atacante | ✅ Nenhum (silêncio total) | Nenhum (DROP) |
| Ambientes mínimos/VM | ✅ Funciona | Pode falhar |

---

## 🚀 Instalação e Uso

### Pré-requisitos

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install python3 iproute2 python3-systemd

# RHEL / Fedora / CentOS
sudo dnf install python3 iproute systemd-python3
```

### Configuração

Edite `containment.py` antes de rodar:

```python
MAX_FAILURES: Final[int] = 5      # falhas para acionar bloqueio
TIME_WINDOW: Final[float] = 60.0  # janela em segundos

WHITELIST_RAW = [
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",
    "SEU.IP.DE.GESTAO.AQUI",  # ← IMPORTANTE: adicione antes de rodar
]
```

> ⚠️ **Adicione seu IP de gestão na whitelist antes de iniciar.**
> O Citadel pode bloquear sua própria sessão SSH se você esquecer.

### Execução

```bash
# Versão com systemd-python (recomendada)
sudo python3 citadel.py

# Versão bypass (sem systemd-python — ambientes mínimos, Vagrant, containers)
sudo python3 citadel_bypass.py
```

### Como verificar o nome da sua unit SSH

```bash
systemctl status ssh sshd
# Debian/Ubuntu recentes → ssh.service
# RHEL/Fedora/CentOS    → sshd.service
```

Se necessário, ajuste em `build_journal_reader()`.

---

## 📺 Demo — Citadel vs Hydra

```
[Kali Linux - Atacante]                [Debian - Citadel]
─────────────────────────────────────────────────────────

$ hydra -l root -P fasttrack.txt       [CITADEL] Fase 3 iniciada.
  ssh://192.168.100.10 -t 4              Limiar: 5 falhas em 60s

[DATA] attacking ssh://192.168.100.10  [ALERTA] IP: 192.168.100.11
                                         Usuário: root | Falhas: 1/5
                                       [ALERTA] IP: 192.168.100.11
                                         Usuário: root | Falhas: 2/5
                                       [ALERTA] IP: 192.168.100.11
                                         Usuário: root | Falhas: 3/5
                                       [ALERTA] IP: 192.168.100.11
                                         Usuário: root | Falhas: 4/5
                                       [ALERTA] IP: 192.168.100.11
                                         Usuário: root | Falhas: 5/5
                                       [CITADEL][LIMIAR] Bloqueando...
                                       [CITADEL][BLOQUEIO] ✓
                                         192.168.100.11 → blackhole

[tentando... tentando... timeout...]
[sem resposta — pacotes descartados
 silenciosamente pelo kernel]
```

---

## 🔧 Como Rodar como Serviço systemd

Crie `/etc/systemd/system/citadel.service`:

```ini
[Unit]
Description=Citadel — Active Defense SOAR
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/citadel/citadel.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now citadel
sudo systemctl status citadel
```

---

## ⚠️ Aviso Legal / Disclaimer

> Este projeto foi desenvolvido **exclusivamente para fins educacionais** em ambientes de laboratório controlados (VirtualBox, Vagrant, HackTheBox, TryHackMe).
>
> **Não utilize em sistemas que você não possui ou não tem autorização explícita por escrito para testar.**
>
> O autor não se responsabiliza por uso indevido desta ferramenta. Segurança ofensiva e defensiva deve ser praticada dentro dos limites legais e éticos.

---

## 📄 Licença

MIT — veja [LICENSE](LICENSE) para detalhes.

---

*Construído linha a linha como exercício de Purple Team. Red pensa no ataque. Blue pensa na defesa. Purple pensa nos dois ao mesmo tempo.*
