#!/usr/bin/env python3
"""
Ponte ELC 6012 NET <-> MQTT <-> Home Assistant (auto-descoberta).

O controle do ELC 6012 NET passa pela nuvem Intelbras (relay amt8000) —
ver PROTOCOLO-ELC6012NET.md. Esta ponte mantém UMA sessão cloud aberta (um
login só) e consulta o status nela a cada --poll segundos. O relay aceita uma
sessão por painel: enquanto a ponte estiver conectada, o app Guardian mostra
"central desconectada". Publica:

  - alarm_control_panel "Cerca elétrica" (arm_away / disarm)
  - switch "Choque" (liga/desliga só o choque, sem mexer no alarme)
  - binary_sensor por zona (aberta) — 8 zonas
  - switch por zona: bypass (anula/reativa; só com o alarme desarmado)
  - binary_sensor de disparo (alguma zona disparada)
  - binary_sensor "choque" (alta tensão ativa na cerca)
  - sensor de sinal (%)
  - binary_sensor de conectividade da ponte
  - sensor "Último evento" e entidade event com os eventos novos do painel

Requisitos: python3, paho-mqtt (pip install paho-mqtt)

Uso (senhas por variável de ambiente para não aparecerem no `ps`):
  export ELC_PASSWORD=SUASENHA MQTT_PASSWORD=SENHA_MQTT
  python3 elc6012_ha_mqtt.py --mac 001A3F123456 \
      --mqtt 192.168.0.10 --mqtt-user ha --poll 15

Descubra o MAC na rede local com:
  python3 elc6012_client.py --host <ip-do-elc> probe
"""
import argparse
import json
import os
import queue
import sys
import threading
import time

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Instale paho-mqtt:  pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)

from elc6012_client import (NUM_ZONES, ElcCloudSession, PanelRefused, normalize_mac,
                            password_bytes)

POLL_DEFAULT = 15
POLL_MIN = 10   # numa sessão aberta cada consulta leva ~0,3 s

# Tipos da entidade event (para automações); "Acesso por download" (1410), que
# o relay grava a cada login, é ignorado.
EVENT_TYPES = ["disparo", "panico", "arme", "desarme", "bypass", "energia", "outro"]
EVENT_ACCESS = "1410"


def event_type(ev):
    """Classifica um evento de parse_events() num dos EVENT_TYPES."""
    eee = ev["codigo"][1:]
    if eee in ("130", "133"):
        return "disparo"
    if eee in ("120", "122", "146"):
        return "panico"
    if ev["evento"].startswith("Desarme"):
        return "desarme"
    if ev["evento"].startswith("Arme"):
        return "arme"
    if eee == "570":
        return "bypass"
    if eee in ("301", "342"):
        return "energia"
    return "outro"


class Bridge:
    def __init__(self, mac, password, mqtt_host, mqtt_port, mqtt_user,
                 mqtt_pass, poll, topic_prefix="elc6012"):
        self.mac = normalize_mac(mac)
        self.password = password
        self.poll = max(POLL_MIN, poll)
        self.prefix = topic_prefix
        self.mqtt = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                                client_id=f"elc6012-{self.mac}", protocol=mqtt.MQTTv311)
        if mqtt_user:
            self.mqtt.username_pw_set(mqtt_user, mqtt_pass or "")
        self.mqtt.on_connect = self._on_connect
        self.mqtt.on_message = self._on_message
        # LWT: se a ponte morrer/cair, o broker marca tudo como indisponível
        self.mqtt.will_set(f"{self.prefix}/online/state", payload="OFF", retain=True)
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.stop_event = threading.Event()
        # Comandos do HA são enfileirados e executados pelo loop principal:
        # uma única sessão cloud por vez (o relay limita sessões, e um poll em
        # andamento não pode sobrescrever o estado novo de um arme/desarme).
        self.commands = queue.Queue()
        self._lock = threading.RLock()   # _last_pub/_last_status: loop principal x thread do paho
        self._last_pub = {}      # publish-on-change: evita re-publicar estados iguais
        self._last_status = None  # último status válido (None = painel inacessível)
        self.session = None       # sessão cloud persistente (só o loop principal usa)
        self._seen_events = None  # registros brutos da última leitura da página 0

    # -- MQTT ---------------------------------------------------------------

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        print(f"[mqtt] conectado ({reason_code})")
        client.subscribe(f"{self.prefix}/alarm/set")
        client.subscribe(f"{self.prefix}/shock/set")
        client.subscribe(f"{self.prefix}/zone/+/bypass/set")
        self._publish_discovery()
        with self._lock:
            self._last_pub.clear()   # republica tudo após (re)conexão
            # O broker publicou o LWT (OFF retido) quando caímos; republica o
            # último estado já, sem esperar o próximo poll (que pode estar em backoff).
            if self._last_status is not None:
                self._publish_status(self._last_status)
            else:
                self._pub("online/state", "OFF")

    def _on_message(self, client, userdata, msg):
        # Um comando retido seria reexecutado a cada reconexão da ponte.
        if msg.retain:
            print(f"[mqtt] ignorando comando retido em {msg.topic}")
            return
        cmd = msg.payload.decode(errors="replace").strip().upper()
        if msg.topic.endswith("/shock/set"):
            cmd = f"SHOCK_{cmd}"   # SHOCK_ON / SHOCK_OFF
        elif msg.topic.endswith("/bypass/set"):
            zone = msg.topic.split("/")[-3]   # <prefix>/zone/<n>/bypass/set
            cmd = f"BYPASS_{cmd}_{zone}"      # BYPASS_ON_3 / BYPASS_OFF_3
        print(f"[mqtt] comando recebido: {cmd}")
        valid = {"ARM_AWAY", "DISARM", "SHOCK_ON", "SHOCK_OFF"}
        valid |= {f"BYPASS_{v}_{z}" for v in ("ON", "OFF") for z in range(1, NUM_ZONES + 1)}
        if cmd not in valid:
            print(f"[mqtt] comando não suportado pelo ELC: {cmd}")
            return
        self.commands.put(cmd)

    def _execute(self, cmd):
        """Executa o comando; retorna False se falhou.

        Falha de comando (ex.: NACK 39 "zonas abertas") não marca a ponte como
        offline — quem decide a disponibilidade é o poll, que o loop principal
        antecipa após a falha para ressincronizar o estado."""
        try:
            s = self._session()
            if cmd == "ARM_AWAY":
                st = s.arm()
            elif cmd == "DISARM":
                st = s.disarm()
            elif cmd.startswith("SHOCK_"):
                st = s.set_shock(cmd == "SHOCK_ON")
            else:
                _, on_off, zone = cmd.split("_")
                st = s.set_bypass(int(zone), on_off == "ON")
        except PanelRefused as e:
            # O painel respondeu (recusando): a sessão continua boa.
            print(f"[!] {cmd} recusado: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[!] falha ao executar {cmd}: {e}", file=sys.stderr)
            self._drop_session()
            return False
        self._publish_status(st)
        return True

    # -- sessão cloud -----------------------------------------------------------

    def _session(self):
        """A sessão aberta; abre (login) se não houver."""
        if self.session is None:
            s = ElcCloudSession(self.mac, self.password)
            s.open()
            self.session = s
            print("[elc] sessão aberta")
        return self.session

    def _drop_session(self):
        """Fecha a sessão após erro de comunicação; o próximo uso reconecta."""
        if self.session is not None:
            self.session.close()
            self.session = None

    def _pub(self, topic, payload, retain=True):
        """Publica apenas se o valor mudou desde a última publicação."""
        with self._lock:
            if self._last_pub.get(topic) == payload:
                return
            self._last_pub[topic] = payload
            self.mqtt.publish(f"{self.prefix}/{topic}", payload, retain=retain)

    def _mark_offline(self):
        with self._lock:
            self._last_status = None
            self._pub("online/state", "OFF")

    # -- descoberta HA --------------------------------------------------------

    def _publish_discovery(self):
        # Identificado pelo MAC: duas pontes (dois ELCs) não se misturam no HA.
        mac_colons = ":".join(self.mac[i:i + 2] for i in range(0, 12, 2)).lower()
        dev = {"name": "ELC 6012 NET", "identifiers": [f"elc6012_{self.mac}"],
               "connections": [["mac", mac_colons]],
               "manufacturer": "Intelbras", "model": "ELC 6012 NET (cerca elétrica)"}
        # Entidades do dispositivo ficam indisponíveis junto com a ponte, em vez
        # de exibirem o último valor como se fosse atual.
        avail = {"availability_topic": f"{self.prefix}/online/state",
                 "payload_available": "ON", "payload_not_available": "OFF"}
        on_off = {"payload_on": "ON", "payload_off": "OFF"}

        def config(component, key, entity_id, cfg):
            # default_entity_id: sem ele o HA prefixa o nome do dispositivo
            # (ex.: alarm_control_panel.elc_6012_net_cerca_eletrica). Só vale na
            # criação da entidade; requer HA 2025.10+.
            cfg.update({"unique_id": f"{self.prefix}_{key}",
                        "default_entity_id": f"{component}.{entity_id}",
                        "device": dev})
            self.mqtt.publish(f"homeassistant/{component}/{self.prefix}/{key}/config",
                              json.dumps(cfg), retain=True)

        config("alarm_control_panel", "alarm", "cerca_eletrica", {
            "name": "Cerca elétrica",
            "state_topic": f"{self.prefix}/alarm/state",
            "command_topic": f"{self.prefix}/alarm/set",
            "supported_features": ["arm_away"],   # o ELC só arma em modo único
            "payload_disarm": "DISARM",
            "payload_arm_away": "ARM_AWAY",
            **avail,
        })

        for z in range(1, NUM_ZONES + 1):
            config("binary_sensor", f"zone{z}", f"zona_{z}", {
                "name": f"Zona {z}",
                "state_topic": f"{self.prefix}/zone/{z}/state",
                "device_class": "opening",
                **on_off, **avail,
            })
            # Zona anulada (bypass): ignorada pelo painel até ser reativada.
            # Só com o alarme desarmado — senão o comando falha e o switch volta.
            config("switch", f"bypass_switch{z}", f"bypass_zona_{z}", {
                "name": f"Bypass zona {z}",
                "state_topic": f"{self.prefix}/zone/{z}/bypass",
                "command_topic": f"{self.prefix}/zone/{z}/bypass/set",
                "icon": "mdi:shield-off-outline",
                **on_off, **avail,
            })

        # Remove entidades de versões anteriores da ponte: zonas 9-16 (o ELC
        # tem 8) e os binary_sensors de bypass (agora são switches).
        for z in range(1, 17):
            stale = [f"bypass{z}"] + ([f"zone{z}"] if z > NUM_ZONES else [])
            for key in stale:
                self.mqtt.publish(f"homeassistant/binary_sensor/{self.prefix}/{key}/config",
                                  "", retain=True)

        config("binary_sensor", "triggered", "disparo", {
            "name": "Disparo",
            "state_topic": f"{self.prefix}/triggered/state",
            "device_class": "safety",
            **on_off, **avail,
        })

        config("binary_sensor", "shock", "choque_na_cerca", {
            "name": "Choque na cerca",
            "state_topic": f"{self.prefix}/shock/state",
            "device_class": "power",
            **on_off, **avail,
        })

        # Liga/desliga só o choque (partição 2), independente do alarme.
        config("switch", "shock_switch", "choque", {
            "name": "Choque",
            "state_topic": f"{self.prefix}/shock/state",
            "command_topic": f"{self.prefix}/shock/set",
            "icon": "mdi:flash",
            **on_off, **avail,
        })

        # Eventos do buffer do painel (lidos a cada poll, página 0).
        config("sensor", "last_event", "ultimo_evento_cerca", {
            "name": "Último evento",
            "state_topic": f"{self.prefix}/event/last",
            "json_attributes_topic": f"{self.prefix}/event/last/attributes",
            "icon": "mdi:history",
            **avail,
        })
        config("event", "events", "cerca_eletrica", {
            "name": "Eventos",
            "state_topic": f"{self.prefix}/event/fired",
            "event_types": EVENT_TYPES,
            **avail,
        })

        config("sensor", "signal", "sinal_elc", {
            "name": "Sinal ELC",
            "state_topic": f"{self.prefix}/signal/state",
            "unit_of_measurement": "%",
            "state_class": "measurement",
            **avail,
        })

        # Sem availability: este sensor É a disponibilidade (OFF = desconectado).
        config("binary_sensor", "online", "ponte_elc", {
            "name": "Ponte ELC",
            "state_topic": f"{self.prefix}/online/state",
            "device_class": "connectivity",
            **on_off,
        })

    # -- polling/publicação ---------------------------------------------------

    def _publish_status(self, st):
        if st["zonas_disparadas"]:
            state = "triggered"
        elif st["sistema_armado"]:
            # Só o bit do alarme: ele arma sem o choque (partição 1, validado),
            # e "armado" do app ([30].0 AND [31].0) mostraria disarmed nesse caso.
            # O choque tem entidades próprias (switch/binary_sensor).
            state = "armed_away"
        else:
            state = "disarmed"

        with self._lock:
            self._last_status = st
            self._pub("online/state", "ON")
            self._pub("alarm/state", state)
            for z in range(1, NUM_ZONES + 1):
                self._pub(f"zone/{z}/state", "ON" if z in st["zonas_abertas"] else "OFF")
                self._pub(f"zone/{z}/bypass", "ON" if z in st["zonas_bypass"] else "OFF")
            self._pub("triggered/state", "ON" if st["zonas_disparadas"] else "OFF")
            self._pub("shock/state", "ON" if st["choque"] else "OFF")
            if st["sinal_pct"] is not None:
                self._pub("signal/state", str(st["sinal_pct"]))
        print(f"[estado] {state}; choque={st['choque']} "
              f"abertas={st['zonas_abertas']} disparo={st['zonas_disparadas']} "
              f"bypass={st['zonas_bypass']}")

    def _process_events(self, evs):
        """Publica os eventos novos da página 0 (mais novo primeiro).

        Na primeira leitura só memoriza o que já existia (e mostra o último
        evento no sensor); depois, publica cada registro que não estava na
        leitura anterior, do mais antigo para o mais novo."""
        raws = [ev["bruto"] for ev in evs]
        relevant = [ev for ev in evs if ev["codigo"] != EVENT_ACCESS]
        if self._seen_events is None:
            self._seen_events = set(raws)
            if relevant:
                self._publish_last_event(relevant[0])
            return
        new = []
        for ev in evs:
            if ev["bruto"] in self._seen_events:
                break
            new.append(ev)
        self._seen_events = set(raws)
        for ev in reversed(new):
            if ev["codigo"] == EVENT_ACCESS:
                continue
            attrs = self._publish_last_event(ev)
            self.mqtt.publish(f"{self.prefix}/event/fired", json.dumps(attrs), retain=False)
            print(f"[evento] {ev['data']} {ev['hora']} {ev['evento']} ({ev['particao']})")

    def _publish_last_event(self, ev):
        attrs = {"event_type": event_type(ev), "evento": ev["evento"], "particao": ev["particao"],
                 "zona_usuario": ev["zona_usuario"], "data": ev["data"], "hora": ev["hora"],
                 "codigo": ev["codigo"]}
        label = ev["evento"] if ev["particao"] == "—" else f"{ev['evento']} · {ev['particao']}"
        self._pub("event/last/attributes", json.dumps(attrs))
        self._pub("event/last", label)
        return attrs

    def poll_once(self):
        try:
            s = self._session()
            st = s.status()
        except Exception as e:
            print(f"[!] falha ao consultar status: {e}", file=sys.stderr)
            self._drop_session()
            self._mark_offline()
            return False
        self._publish_status(st)
        try:
            self._process_events(s.events_page(0))
        except Exception as e:
            # O status já foi publicado; só reconecta na próxima consulta.
            print(f"[!] falha ao ler eventos: {e}", file=sys.stderr)
            self._drop_session()
        return True

    def run(self):
        self.mqtt.connect(self.mqtt_host, self.mqtt_port, keepalive=60)
        self.mqtt.loop_start()
        failures = 0
        next_poll = time.monotonic()
        while not self.stop_event.is_set():
            # Espera até o próximo poll, mas acorda na hora se chegar um comando.
            try:
                cmd = self.commands.get(timeout=max(0.0, next_poll - time.monotonic()))
            except queue.Empty:
                cmd = None
            if cmd is not None:
                # Em caso de sucesso a resposta já é o novo status; se falhou,
                # o estado real é incerto: consulta logo.
                if not self._execute(cmd):
                    next_poll = time.monotonic()
                continue

            if self.poll_once():
                failures = 0
                wait = self.poll
            else:
                # backoff (ex.: NACK 50 — outra sessão ativa): 2x, até 10 min
                failures += 1
                wait = min(self.poll * (2 ** failures), 600)
                print(f"[!] nova tentativa em {wait}s")
            next_poll = time.monotonic() + wait
        self._drop_session()
        self.mqtt.loop_stop()


def main():
    # Sob systemd o stdout não é um terminal e ficaria em buffer de bloco:
    # os logs chegariam ao journal atrasados. Uma linha = um flush.
    sys.stdout.reconfigure(line_buffering=True)

    ap = argparse.ArgumentParser(description="Ponte ELC 6012 NET -> MQTT -> Home Assistant")
    ap.add_argument("--mac", required=True, help="MAC do ELC (ex.: 001A3F123456)")
    ap.add_argument("--password", default=os.environ.get("ELC_PASSWORD"),
                    help="senha do eletrificador (padrão: variável ELC_PASSWORD)")
    ap.add_argument("--mqtt", default="127.0.0.1", help="host do broker MQTT")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--mqtt-user", default=None)
    ap.add_argument("--mqtt-pass", default=os.environ.get("MQTT_PASSWORD"),
                    help="senha do broker (padrão: variável MQTT_PASSWORD)")
    ap.add_argument("--poll", type=int, default=POLL_DEFAULT,
                    help=f"intervalo de polling em segundos (mínimo {POLL_MIN}, padrão {POLL_DEFAULT})")
    ap.add_argument("--prefix", default="elc6012", help="prefixo dos tópicos MQTT")
    ns = ap.parse_args()
    if not ns.password:
        ap.error("informe a senha do eletrificador (variável ELC_PASSWORD ou --password)")
    # Valida já na partida: erro de digitação não deve virar falha de login
    # repetida a cada ciclo de polling.
    try:
        normalize_mac(ns.mac)
        password_bytes(ns.password)
    except ValueError as e:
        ap.error(str(e))

    b = Bridge(ns.mac, ns.password, ns.mqtt, ns.mqtt_port,
               ns.mqtt_user, ns.mqtt_pass, ns.poll, ns.prefix)
    try:
        b.run()
    except KeyboardInterrupt:
        print("encerrando...")


if __name__ == "__main__":
    main()
