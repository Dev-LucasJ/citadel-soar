"""
╔══════════════════════════════════════════════════════════════╗
║       PROJETO CITADEL — Fase 3: "Motor de Contenção"         ║
║              Módulo: containment.py                          ║
╠══════════════════════════════════════════════════════════════╣
║  Responsabilidades:                                          ║
║    1. Whitelist  → ipaddress (IPs e CIDRs confiáveis)        ║
║    2. Memória    → dict com timestamps + expurgo automático  ║
║    3. Bloqueio   → blackhole (ip route) + iptables fallback  ║
╚══════════════════════════════════════════════════════════════╝
"""

import ipaddress
import subprocess
import time
from collections import deque
from typing import Final

# ══════════════════════════════════════════════════════════════
# CONFIGURAÇÃO — ajuste aqui, sem tocar na lógica
# ══════════════════════════════════════════════════════════════

# Número de falhas para acionar o bloqueio
MAX_FAILURES: Final[int] = 5

# Janela de tempo em segundos para contar as falhas
TIME_WINDOW: Final[float] = 60.0

# IPs e CIDRs que jamais serão bloqueados.
# Adicione seu IP de gestão aqui ANTES de rodar em produção.
WHITELIST_RAW: Final[list[str]] = [
    "127.0.0.1",
    "::1",               # loopback IPv6
#    "192.168.0.0/16",    # rede local típica
    "10.0.0.0/8",        # RFC-1918 corporativo
    # "203.0.113.50",    # exemplo: seu IP fixo de gestão
]

# ══════════════════════════════════════════════════════════════
# PRÉ-PROCESSAMENTO DA WHITELIST
#
# Convertemos strings para objetos ipaddress UMA VEZ na carga
# do módulo. Assim a checagem no loop quente é só uma iteração
# sobre objetos já prontos — sem parsing a cada evento.
# ══════════════════════════════════════════════════════════════
_WHITELIST: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

for _entry in WHITELIST_RAW:
    try:
        # strict=False → aceita "192.168.1.5/24" sem lançar erro
        # (trata como rede "192.168.1.0/24" automaticamente)
        _WHITELIST.append(ipaddress.ip_network(_entry, strict=False))
    except ValueError as _e:
        print(f"[CITADEL][AVISO] Entrada inválida na whitelist ignorada: '{_entry}' → {_e}")


# ══════════════════════════════════════════════════════════════
# CLASSE ThreatMemory — Memória de Curto Prazo
# ══════════════════════════════════════════════════════════════

class ThreatMemory:
    """
    Rastreia tentativas de falha por IP dentro de uma janela temporal.

    Estrutura interna:
    ──────────────────
    _log: dict[str, deque[float]]

      Chave   → IP do atacante (string)
      Valor   → deque de timestamps (float, Unix epoch)
                de cada falha registrada para aquele IP

    Por que deque e não list?
      • deque com maxlen=MAX_FAILURES tem inserção O(1) e descarte
        automático do elemento mais antigo quando cheio.
      • Isso nos dá um "sliding window" sem nunca precisar fazer
        slicing ou copiar listas — memória e CPU mínimos.

    Por que não usar um Counter ou um int simples?
      • Um inteiro não carrega informação temporal — não dá para
        saber se as 5 falhas ocorreram nos últimos 60 s ou nas
        últimas 24 h sem um timestamp por evento.
    """

    def __init__(self) -> None:
        # Cada IP mapeia para uma fila de timestamps das falhas
        # maxlen garante que nunca guardamos mais que MAX_FAILURES
        # timestamps por IP — o mais antigo é descartado sozinho
        self._log: dict[str, deque[float]] = {}

        # Contador de ciclos para amortizar o custo do expurgo global.
        # Expurgar a cada evento seria caro; a cada N eventos é barato.
        self._events_since_purge: int = 0
        self._PURGE_INTERVAL: Final[int] = 50  # expurga a cada 50 eventos

    # ──────────────────────────────────────────────────────────
    # MÉTODO PRINCIPAL: registrar uma falha e decidir se bloqueia
    # ──────────────────────────────────────────────────────────
    def record(self, ip: str) -> bool:
        """
        Registra uma falha para o IP e retorna True se o limiar
        de bloqueio foi atingido.

        O fluxo interno:
          1. Obtém (ou cria) a deque de timestamps do IP.
          2. Expurga timestamps fora da janela temporal (sliding window).
          3. Adiciona o timestamp atual.
          4. Verifica se o número de falhas válidas >= MAX_FAILURES.
          5. Periodicamente executa o expurgo global de IPs inativos.

        Returns:
            True  → bloquear este IP agora
            False → ainda abaixo do limiar, apenas monitorar
        """
        now: float = time.monotonic()
        # time.monotonic() é imune a ajustes do relógio do sistema
        # (NTP, fuso horário, etc.) — mais seguro que time.time()
        # para medir intervalos.

        # Cria a deque se for a primeira falha deste IP.
        # maxlen=MAX_FAILURES: quando cheio, o append() descarta
        # o timestamp mais antigo automaticamente (sem código extra).
        if ip not in self._log:
            self._log[ip] = deque(maxlen=MAX_FAILURES)

        queue: deque[float] = self._log[ip]

        # ── EXPURGO DO SLIDING WINDOW ───────────────────────────
        # Remove timestamps mais velhos que TIME_WINDOW.
        # Como a deque está em ordem cronológica (appendleft seria
        # inverso), os mais antigos estão na esquerda (index 0).
        # popleft() é O(1) — ideal para deque.
        #
        # Exemplo visual (TIME_WINDOW=60s, now=100):
        #   Antes:  [30.1, 55.7, 70.2, 95.0]
        #   Expurgo: 30.1 é descartado (100-30.1 > 60)
        #            55.7 também      (100-55.7 > 60)
        #   Depois: [70.2, 95.0]  ← apenas falhas recentes
        while queue and (now - queue[0]) > TIME_WINDOW:
            queue.popleft()

        # Registra a falha atual
        queue.append(now)

        # ── EXPURGO GLOBAL AMORTIZADO ───────────────────────────
        # Problema: IPs que pararam de atacar ficam em _log para
        # sempre, vazando RAM ao longo de dias/semanas.
        # Solução: a cada PURGE_INTERVAL eventos, varremos o dict
        # inteiro e removemos IPs com deques vazias.
        #
        # "Amortizado" significa que o custo O(n) do purge é
        # diluído sobre PURGE_INTERVAL eventos, resultando em
        # custo médio O(1) por evento — transparente ao loop.
        self._events_since_purge += 1
        if self._events_since_purge >= self._PURGE_INTERVAL:
            self._purge_stale_ips(now)
            self._events_since_purge = 0

        # Decisão de bloqueio: atingiu o limiar?
        return len(queue) >= MAX_FAILURES

    def _purge_stale_ips(self, now: float) -> None:
        """
        Remove IPs cujos timestamps mais recentes já expiraram.

        Chamado internamente, nunca pelo loop principal.

        Estratégia:
          • Um IP é "stale" se sua deque estiver vazia após o
            expurgo de sliding window (todas as falhas são antigas).
          • Usamos list() para materializar as chaves antes de
            deletar — nunca modifique um dict durante iteração.
        """
        stale: list[str] = [
            ip for ip, queue in self._log.items()
            # Reaplica o critério de janela: descarta eventos velhos
            if not any((now - ts) <= TIME_WINDOW for ts in queue)
        ]
        for ip in stale:
            del self._log[ip]

        if stale:
            print(f"[CITADEL][MEM] Expurgados {len(stale)} IP(s) inativo(s) da memória.")

    def failure_count(self, ip: str) -> int:
        """Retorna quantas falhas válidas (dentro da janela) o IP tem."""
        if ip not in self._log:
            return 0
        now = time.monotonic()
        return sum(1 for ts in self._log[ip] if (now - ts) <= TIME_WINDOW)


# ══════════════════════════════════════════════════════════════
# FUNÇÕES DE WHITELIST E BLOQUEIO
# ══════════════════════════════════════════════════════════════

def is_whitelisted(ip: str) -> bool:
    """
    Verifica se o IP pertence a alguma rede da whitelist.

    Usa ipaddress.ip_address() para criar um objeto comparável,
    depois testa membership (in) contra cada rede pré-compilada.

    Returns:
        True  → IP confiável, ignorar o evento
        False → IP desconhecido, processar normalmente
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # IP mal-formado que passou pelo regex (não deveria ocorrer,
        # mas defesa em profundidade nunca é demais)
        return False

    return any(addr in network for network in _WHITELIST)


def _run_cmd(cmd: list[str], timeout: int = 5) -> tuple[bool, str]:
    """
    Executa um comando de sistema e retorna (sucesso, stderr).

    Centraliza a chamada subprocess para que _block_via_blackhole()
    e _block_via_iptables() não repitam o mesmo bloco try/except.
    Nunca usa 'sudo' — o processo pai deve ser root ou ter as
    capabilities necessárias (CAP_NET_ADMIN, CAP_NET_RAW).

    Returns:
        (True, "")        → comando executou com returncode 0
        (False, "<msg>")  → falha; msg descreve a causa
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()

    except FileNotFoundError:
        return False, f"binário não encontrado: '{cmd[0]}'"
    except PermissionError:
        return False, "sem privilégio (execute como root ou com CAP_NET_ADMIN)"
    except subprocess.TimeoutExpired:
        return False, f"timeout após {timeout}s"


def _block_via_blackhole(ip: str) -> bool:
    """
    Método primário: rota blackhole via 'ip route'.

    Comando: ip route add blackhole <ip>/32

    Como funciona:
      O kernel descarta silenciosamente qualquer pacote destinado
      a esse host antes de chegar à pilha TCP/IP — equivalente a
      um DROP no nível de roteamento, mais eficiente que iptables
      porque atua antes do netfilter.

    Vantagem sobre iptables em ambiente offline/Vagrant:
      'ip' (iproute2) está presente em praticamente qualquer Linux
      moderno; iptables pode estar ausente ou ter módulos faltando
      em imagens mínimas de VM.

    EEXIST ("File exists"):
      O kernel retorna este erro se a rota já existe. Tratamos como
      sucesso — o bloqueio já está ativo, o objetivo foi atingido.
      É seguro e correto aceitar esse estado idempotente.

    Requer: root ou CAP_NET_ADMIN.
    """
    # /32 garante que apenas este host específico seja afetado,
    # nunca uma subnet inteira por um IP sem máscara.
    ok, stderr = _run_cmd(["ip", "route", "add", "blackhole", f"{ip}/32"])

    if ok:
        print(f"[CITADEL][BLOQUEIO] ✓ IP {ip} → blackhole (ip route).")
        return True

    # EEXIST: rota já existe — bloqueio já estava ativo, aceita como sucesso
    if "File exists" in stderr or "EEXIST" in stderr:
        print(f"[CITADEL][BLOQUEIO] IP {ip} já estava no blackhole (sem ação necessária).")
        return True

    # Falha real: loga o stderr original para diagnóstico
    print(f"[CITADEL][ERRO] blackhole falhou para {ip}: {stderr}")
    return False


def _block_via_iptables(ip: str) -> bool:
    """
    Método de fallback: regra DROP na chain INPUT via iptables.

    Comando: iptables -I INPUT -s <ip> -j DROP

    Por que -I (insert) e não -A (append)?
      -I insere no TOPO da chain. Se houver um ACCEPT geral antes
      do ponto de inserção de -A, o DROP nunca seria alcançado.
      -I garante precedência absoluta independente das regras existentes.

    Requer: root ou CAP_NET_ADMIN + módulo nf_tables/iptables carregado.
    """
    ok, stderr = _run_cmd(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])

    if ok:
        print(f"[CITADEL][BLOQUEIO] ✓ IP {ip} bloqueado via iptables (fallback).")
        return True

    print(f"[CITADEL][ERRO] iptables falhou para {ip}: {stderr}")
    return False


def block_ip(ip: str) -> bool:
    """
    Bloqueia o IP usando a melhor estratégia disponível.

    Ordem de tentativa:
      1. Blackhole via 'ip route'  → mais eficiente, funciona offline,
                                     disponível em imagens mínimas
      2. DROP via iptables         → fallback se iproute2 não disponível
                                     ou sem suporte a blackhole no kernel

    A separação em funções privadas (_block_via_*) mantém esta função
    legível como um dispatcher, sem misturar lógica de dois mecanismos.

    Returns:
        True  → ao menos um método aplicou o bloqueio com sucesso
        False → ambos falharam (sem privilégio, binários ausentes, etc.)
    """
    if _block_via_blackhole(ip):
        return True

    print(f"[CITADEL][AVISO] Blackhole indisponível para {ip}. Tentando iptables...")
    return _block_via_iptables(ip)
