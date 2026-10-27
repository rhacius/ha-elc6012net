#!/usr/bin/env python3
"""Teste: uma única sessão na nuvem aguenta consultas periódicas?

Até a 1.0.2 a ponte abria uma sessão (e um login) por poll, e cada login
gravava um "Acesso por download" no buffer de 64 eventos do ELC. Este teste
validou a sessão persistente adotada na 1.1.0 (12 min sem queda). Pare a ponte
antes de rodá-lo: o relay aceita uma sessão por painel.

Fases (≈ 12 min): 10 consultas a cada 30 s, 5 a cada 60 s e 1 após 120 s
parada. Ao cair, mostra em que ponto caiu. No fim, lê a página 0 de eventos
na mesma sessão.

Uso (na raiz do projeto):
  export ELC_PASSWORD=SUASENHA
  python3 tools/sessao_persistente.py --mac 001A3F123456
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from elc6012_client import ElcCloudSession  # noqa: E402

PHASES = [(30, 10), (60, 5), (120, 1)]   # (intervalo em s, consultas)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mac", required=True)
    ap.add_argument("--password", default=os.environ.get("ELC_PASSWORD", ""))
    ns = ap.parse_args()
    if not ns.password:
        ap.error("defina ELC_PASSWORD")

    start = time.monotonic()
    s = ElcCloudSession(ns.mac, ns.password)
    s.open()
    print(f"{time.strftime('%H:%M:%S')}  sessão aberta (1 login)")
    total = 0
    try:
        for interval, count in PHASES:
            for _ in range(count):
                time.sleep(interval)
                t0 = time.monotonic()
                try:
                    st = s.status()
                except Exception as e:
                    print(f"{time.strftime('%H:%M:%S')}  CAIU após {total} consultas, "
                          f"{time.monotonic() - start:.0f} s de sessão, intervalo {interval} s: "
                          f"{type(e).__name__}: {e}")
                    return
                total += 1
                print(f"{time.strftime('%H:%M:%S')}  #{total:2d} intervalo {interval:3d} s  "
                      f"{(time.monotonic() - t0) * 1000:5.0f} ms  "
                      f"alarme={'on' if st['sistema_armado'] else 'off'} "
                      f"choque={'on' if st['choque'] else 'off'}")
        print(f"\nOK: {total} consultas em {time.monotonic() - start:.0f} s com um único login.")
        print("Página 0 de eventos (mesma sessão):")
        for ev in s.events()[:8]:
            print(f"  {ev['data']} {ev['hora']}  {ev['evento']}  [{ev['codigo']}]")
    finally:
        s.close()


if __name__ == "__main__":
    main()
