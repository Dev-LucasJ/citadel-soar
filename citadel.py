#!/usr/bin/env python3
import re
import sys
import subprocess
import select

from Containment import (
    MAX_FAILURES,
    TIME_WINDOW,
    ThreatMemory,
    block_ip,
    is_whitelisted,
)

_SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>[\w\.\-]+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def extract_data(message: str) -> tuple[str | None, str | None]:
    match = _SSH_FAIL_RE.search(message)
    if match:
        return match.group("ip"), match.group("user")
    return None, None

def build_journal_reader():
    """Modo Bypass: Lê o journalctl via subprocess sem precisar da lib systemd"""
    cmd = [
        "journalctl",
        "-u", "ssh.service",
        "-u", "sshd.service",
        "-f",         # Follow (tail -f)
        "-n", "0",    # Pula os logs antigos
        "--output=cat"
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

def run() -> None:
    print(
        f"[CITADEL] Fase 3 iniciada (Modo Bypass de Rede Ativo).\n"
        f"  Limiar de bloqueio : {MAX_FAILURES} falhas em {TIME_WINDOW}s\n"
        f"  Monitorando SSH... (Ctrl+C para parar)\n"
    )

    process = build_journal_reader()
    memory = ThreatMemory()
    blocked_ips: set[str] = set()

    poll_obj = select.poll()
    poll_obj.register(process.stdout, select.POLLIN)

    try:
        while True:
            # Espera 1 segundo por novos logs sem travar a CPU
            poll_result = poll_obj.poll(1000)
            if not poll_result:
                continue

            message = process.stdout.readline()
            if not message:
                continue

            if "Failed password" not in message:
                continue

            ip, user = extract_data(message)
            if not ip or not user:
                continue

            if is_whitelisted(ip):
                print(f"[CITADEL][WHITE] IP {ip} na whitelist — evento ignorado.")
                continue

            if ip in blocked_ips:
                continue

            should_block = memory.record(ip)
            count = memory.failure_count(ip)
            
            print(
                f"[ALERTA] Tentativa de invasão! "
                f"IP: {ip} | Usuário: {user} | "
                f"Falhas: {count}/{MAX_FAILURES}"
            )

            if should_block:
                print(f"[CITADEL][LIMIAR] IP {ip} atingiu {MAX_FAILURES} falhas. Bloqueando...")
                success = block_ip(ip)
                if success:
                    blocked_ips.add(ip)

    except KeyboardInterrupt:
        print(f"\n[CITADEL] Monitoramento encerrado pelo operador.")
        process.terminate() # Mata o processo filho do journalctl
        sys.exit(0)

if __name__ == "__main__":
    run()
