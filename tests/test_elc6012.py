"""Testes do cliente e da ponte com respostas reais do ELC 6012 NET.

Rodar na raiz do projeto:  python3 -m unittest -v
(os testes da ponte precisam do paho-mqtt; sem ele são pulados)
"""
import contextlib
import io
import json
import socket
import unittest

import elc6012_client as c

from .frames import (EVENTOS_PAG0, EVENTOS_PAG7, FRAMES, NACK_LOGIN, NACK_LOGIN_TRUNCADO,
                     PROBE_MAC, PROBE_MODELO)

try:
    import elc6012_ha_mqtt as bridge_mod
except SystemExit:   # o módulo sai se o paho-mqtt não estiver instalado
    bridge_mod = None

MAC = "001A3F123456"
ACK = bytes.fromhex("00 00 00 00 00 02 f0 fe")
ACK += bytes([c.checksum(ACK)])


class FakeSocket:
    """Socket roteirizado: cada sendall() enfileira a próxima resposta.

    Resposta b"" simula o painel calado (recv dá timeout)."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.sent = []
        self.buf = b""

    def settimeout(self, t):
        pass

    def sendall(self, data):
        self.sent.append(data)
        self.buf += self.responses.pop(0) if self.responses else b""

    def recv(self, n):
        if not self.buf:
            raise socket.timeout
        chunk, self.buf = self.buf[:n], self.buf[n:]
        return chunk

    def close(self):
        pass


def session(*responses):
    s = c.ElcCloudSession(MAC, "1234")
    s.sock = FakeSocket(*responses)
    return s


def with_byte(frame, offset, value):
    """Cópia de um frame real com um byte trocado (checksum recalculado)."""
    b = bytearray(frame)
    b[offset] = value
    b[-1] = c.checksum(b[:-1])
    return bytes(b)


# ---------------------------------------------------------------------------
# Interpretação do status
# ---------------------------------------------------------------------------

class TestParseStatus(unittest.TestCase):
    # nome: (armado, choque, sistema_armado, zonas_bypass, sinal_pct)
    EXPECTED = {
        "armado":         (True,  True,  True,  [],  48),
        "so_choque":      (False, True,  False, [],  48),
        "armado_bypass1": (True,  True,  True,  [1], 50),
        "tudo_desligado": (False, False, False, [],  48),
        "so_alarme":      (False, False, True,  [],  44),
        "choque_bypass2": (False, True,  False, [2], 44),
    }

    def test_frames_reais(self):
        for name, (armado, choque, sistema, bypass, sinal) in self.EXPECTED.items():
            with self.subTest(name):
                st = c.parse_fence_status(FRAMES[name])
                self.assertEqual(st["armado"], armado)
                self.assertEqual(st["choque"], choque)
                self.assertEqual(st["sistema_armado"], sistema)
                self.assertEqual(st["zonas_bypass"], bypass)
                self.assertEqual(st["sinal_pct"], sinal)
                self.assertEqual(st["zonas_abertas"], [])
                self.assertEqual(st["zonas_disparadas"], [])
                self.assertFalse(st["stay"])
                self.assertEqual(st["modelo"], 0x35)

    def test_checksum_e_tamanho(self):
        for name, frame in FRAMES.items():
            with self.subTest(name):
                self.assertEqual(len(frame), c.STATUS_LEN)
                self.assertEqual(c.checksum(frame[:-1]), frame[-1])
                self.assertEqual(frame[6:8], b"\x0b\x4a")

    def test_relogio(self):
        st = c.parse_fence_status(FRAMES["armado"])
        self.assertEqual(st["data_hora"], {"dia": 27, "mes": 10, "ano": 26,
                                           "hora": 9, "min": 9, "seg": 28})

    def test_mac_no_status(self):
        self.assertEqual(FRAMES["armado"][157:163].hex().upper(), MAC)


# ---------------------------------------------------------------------------
# Enquadramento e validação de entrada
# ---------------------------------------------------------------------------

class TestFraming(unittest.TestCase):
    def test_pacotes_de_comando(self):
        # Pacotes enviados nos testes ao vivo (só choque / só alarme / bypass 2).
        cases = [
            ((c.CMD_ARM_DISARM, bytes([2, 1])), "00 00 00 f1 00 04 40 1e 02 01 57"),
            ((c.CMD_ARM_DISARM, bytes([2, 0])), "00 00 00 f1 00 04 40 1e 02 00 56"),
            ((c.CMD_ARM_DISARM, bytes([1, 1])), "00 00 00 f1 00 04 40 1e 01 01 54"),
            ((c.CMD_ARM_DISARM, bytes([1, 0])), "00 00 00 f1 00 04 40 1e 01 00 55"),
            ((c.CMD_BYPASS, bytes([255, 0, 1, 0, 0, 0, 0, 0, 0])),
             "00 00 00 f1 00 0b 40 1f ff 00 01 00 00 00 00 00 00 a4"),
        ]
        for args, expected in cases:
            with self.subTest(expected):
                self.assertEqual(c.packet8000(*args), bytes.fromhex(expected))

    def test_pacote_status_usa_marker_fence(self):
        self.assertEqual(c.packet_fence(c.CMD_FENCE_STATUS)[:4], b"\x00\x00\x8f\xff")

    def test_sondas_locais(self):
        # Sondas documentadas: 01 C4 3A (MAC) e 01 C2 3C (modelo).
        self.assertEqual(c.cloud_packet(0xC4, b""), bytes.fromhex("01 c4 3a"))
        self.assertEqual(c.cloud_packet(0xC2, b""), bytes.fromhex("01 c2 3c"))
        for resp in (PROBE_MAC, PROBE_MODELO):
            self.assertEqual(c.checksum(resp[:-1]), resp[-1])

    def test_senha(self):
        self.assertEqual(c.password_bytes("1234"), bytes([1, 2, 3, 4, 0, 0]))
        self.assertEqual(c.password_bytes("A0F"), bytes([10, 0, 15, 0, 0, 0]))
        for bad in ("", "1234567", "12x4"):
            with self.subTest(bad), self.assertRaises(ValueError):
                c.password_bytes(bad)

    def test_mac(self):
        for mac in ("00:1a:3f:12:34:56", "00-1A-3F-12-34-56", "001a3f123456"):
            self.assertEqual(c.normalize_mac(mac), MAC)
        with self.assertRaises(ValueError):
            c.normalize_mac("001A3F12345")


# ---------------------------------------------------------------------------
# Leitura de frames do relay
# ---------------------------------------------------------------------------

class TestXchg(unittest.TestCase):
    def test_le_so_um_frame(self):
        s = session(FRAMES["armado"] + ACK)
        self.assertEqual(s._xchg(b"x"), FRAMES["armado"])
        self.assertEqual(s.sock.buf, ACK)   # o seguinte fica no socket

    def test_nack_com_byte_do_codigo(self):
        # O len do NACK não conta o código: o cliente lê 1 byte a mais.
        self.assertEqual(session(NACK_LOGIN)._xchg(b"x"), NACK_LOGIN)

    def test_nack_truncado_da_erro_de_checksum(self):
        with self.assertRaisesRegex(ConnectionError, "checksum"):
            session(NACK_LOGIN_TRUNCADO)._xchg(b"x")

    def test_checksum_invalido(self):
        with self.assertRaisesRegex(ConnectionError, "checksum"):
            session(FRAMES["armado"][:-1] + b"\x00")._xchg(b"x")

    def test_login_ok(self):
        login_ok = bytes.fromhex("00 00 00 00 00 03 f0 f0 00")
        login_ok += bytes([c.checksum(login_ok)])
        s = session(ACK, ACK, login_ok)
        s._bind_and_login()
        self.assertEqual(s.sock.sent[2][8:], bytes([1, 1, 2, 3, 4, 0, 0, 0x10, 0x00]) +
                         bytes([s.sock.sent[2][-1]]))

    def test_login_recusado_pelo_relay(self):
        s = session(ACK, ACK, NACK_LOGIN)
        with self.assertRaisesRegex(ConnectionError, "código 50"):
            s._bind_and_login()


# ---------------------------------------------------------------------------
# Comandos (respostas reais)
# ---------------------------------------------------------------------------

class TestComandos(unittest.TestCase):
    def test_shock_off(self):
        s = session(FRAMES["tudo_desligado"])
        st = s.set_shock(False)
        self.assertFalse(st["choque"])
        self.assertEqual(s.sock.sent[0][8:10], bytes([2, 0]))

    def test_alarm_on(self):
        s = session(FRAMES["so_alarme"])
        st = s.set_alarm(True)
        self.assertTrue(st["sistema_armado"])
        self.assertFalse(st["choque"])
        self.assertEqual(s.sock.sent[0][8:10], bytes([1, 1]))

    def test_sem_resposta_confirma_pelo_status(self):
        # Visto ao vivo: o shock-on foi aplicado mas a resposta não veio.
        s = session(b"", FRAMES["so_choque"])
        st = s.set_shock(True)
        self.assertTrue(st["choque"])
        self.assertEqual(int.from_bytes(s.sock.sent[1][6:8], "big"), c.CMD_FENCE_STATUS)

    def test_sem_resposta_nenhuma(self):
        with self.assertRaises(TimeoutError):
            session(b"", b"").set_shock(True)

    def test_nack_do_comando(self):
        nack = bytes.fromhex("00 00 00 00 00 02 f0 fd 27")   # código 39: zonas abertas
        nack += bytes([c.checksum(nack)])
        with self.assertRaisesRegex(RuntimeError, "código 39"):
            session(nack).arm()


class TestBypass(unittest.TestCase):
    def test_anula_zona(self):
        s = session(FRAMES["so_choque"], FRAMES["choque_bypass2"])
        st = s.set_bypass(2, True)
        self.assertEqual(st["zonas_bypass"], [2])
        self.assertEqual(s.sock.sent[1][8:-1], bytes([255, 0, 1, 0, 0, 0, 0, 0, 0]))

    def test_preserva_as_outras_zonas(self):
        # Status desarmado com a zona 1 anulada: anular a 3 mantém a 1.
        antes = with_byte(FRAMES["so_choque"], 62, 0b001)
        depois = with_byte(FRAMES["so_choque"], 62, 0b101)
        s = session(antes, depois)
        self.assertEqual(s.set_bypass(3, True)["zonas_bypass"], [1, 3])
        self.assertEqual(s.sock.sent[1][8:-1], bytes([255, 1, 0, 1, 0, 0, 0, 0, 0]))

    def test_reativa_zona(self):
        s = session(FRAMES["choque_bypass2"], FRAMES["so_choque"])
        self.assertEqual(s.set_bypass(2, False)["zonas_bypass"], [])
        self.assertEqual(s.sock.sent[1][8:-1], bytes([255] + [0] * 8))

    def test_recusa_com_alarme_armado(self):
        s = session(FRAMES["armado"])
        with self.assertRaisesRegex(RuntimeError, "desarme o alarme"):
            s.set_bypass(2, True)
        self.assertEqual(len(s.sock.sent), 1)   # só o status; nenhum 0x401F

    def test_zona_invalida(self):
        for zone in (0, 9):
            with self.subTest(zone), self.assertRaises(ValueError):
                session().set_bypass(zone, True)


# ---------------------------------------------------------------------------
# Eventos (páginas reais + registros sintéticos para casos não vistos)
# ---------------------------------------------------------------------------

def event_page(records):
    """Página 0x3900 no formato real (len=0x82, 129 bytes), com registros dados."""
    body = b"".join(records) + bytes([0xFF] + [0] * 14) * (8 - len(records))
    frame = bytes.fromhex("00 01 00 00 00 82 39 00") + body
    return frame + bytes([c.checksum(frame)])


# Registros sintéticos para casos que ainda não apareceram ao vivo.
DISPARO_Z1 = bytes([1, 1, 3, 0xA, 0, 1, 0, 0, 1, 27, 10, 26, 9, 30, 5])   # E130, alarme, zona 01
RESTAURO_Z1 = bytes([3, 1, 3, 0xA, 0, 1, 0, 0, 1, 27, 10, 26, 9, 32, 0])  # R130


class TestEventos(unittest.TestCase):
    def test_pagina_real_com_comandos(self):
        evs = c.parse_events(EVENTOS_PAG7)
        self.assertEqual(len(evs), 8)
        self.assertEqual([(e["evento"], e["particao"], e["hora"]) for e in evs if e["codigo"] != "1410"], [
            ("Arme remoto", "choque", "09:29:05"),
            ("Desarme remoto", "alarme", "09:27:52"),
            ("Arme remoto", "alarme", "09:27:24"),
            ("Desarme remoto", "choque", "09:27:07"),
        ])
        self.assertEqual(evs[0]["data"], "27/10/26")

    def test_pagina_real_de_acessos(self):
        evs = c.parse_events(EVENTOS_PAG0)
        self.assertEqual({e["evento"] for e in evs}, {"Acesso por download"})
        self.assertEqual(evs[0]["particao"], "—")
        self.assertEqual(evs[0]["hora"], "11:22:40")
        self.assertEqual(evs[-1]["hora"], "11:16:10")   # mais novo primeiro

    def test_sinteticos(self):
        evs = c.parse_events(event_page([DISPARO_Z1, RESTAURO_Z1]))
        self.assertEqual(len(evs), 2)   # os registros FF são ignorados
        self.assertEqual((evs[0]["evento"], evs[0]["codigo"], evs[0]["zona_usuario"]),
                         ("Disparo de zona", "1130", "01"))
        self.assertEqual(evs[1]["evento"], "Disparo de zona (restauração)")
        rec = bytes([1, 9, 9, 9, 0, 2] + [0] * 9)
        self.assertEqual(c.parse_events(event_page([rec]))[0]["evento"], "Evento 1999")

    def test_le_as_8_paginas_sem_esperar_timeout(self):
        s = session(EVENTOS_PAG0, *[EVENTOS_PAG7] * 7)
        evs = s.events()
        self.assertEqual(len(evs), 64)
        self.assertEqual(s.sock.sent[3][:4] + s.sock.sent[3][6:9], b"\x00\x00\x00\x00\x39\x00\x03")
        self.assertEqual(s.sock.buf, b"")

    def test_frame_de_129_bytes_com_len_0x82(self):
        s = session(EVENTOS_PAG7 + ACK)
        self.assertEqual(s._xchg(b"x"), EVENTOS_PAG7)
        self.assertEqual(s.sock.buf, ACK)   # parou no fim do frame

    def test_resposta_errada(self):
        with self.assertRaisesRegex(RuntimeError, "página 0"):
            session(FRAMES["armado"]).events()


# ---------------------------------------------------------------------------
# Ponte MQTT
# ---------------------------------------------------------------------------

class FakeMqtt:
    def __init__(self):
        self.pubs = {}

    def publish(self, topic, payload, retain=False):
        self.pubs[topic] = payload


class FakeMsg:
    def __init__(self, topic, payload, retain=False):
        self.topic, self.payload, self.retain = topic, payload, retain


@unittest.skipIf(bridge_mod is None, "paho-mqtt não instalado")
class TestBridge(unittest.TestCase):
    def setUp(self):
        quiet = contextlib.redirect_stdout(io.StringIO())   # logs da ponte
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        self.b = bridge_mod.Bridge(MAC, "1234", "localhost", 1883, None, None, 60)
        self.b.mqtt = FakeMqtt()

    def publish(self, frame_name):
        self.b._publish_status(c.parse_fence_status(FRAMES[frame_name]))
        return self.b.mqtt.pubs

    def test_estado_do_painel(self):
        # O painel segue só o bit do alarme; o choque tem entidades próprias.
        cases = {"armado": ("armed_away", "ON"), "so_choque": ("disarmed", "ON"),
                 "so_alarme": ("armed_away", "OFF"), "tudo_desligado": ("disarmed", "OFF")}
        for name, (alarm, shock) in cases.items():
            with self.subTest(name):
                pubs = self.publish(name)
                self.assertEqual(pubs["elc6012/alarm/state"], alarm)
                self.assertEqual(pubs["elc6012/shock/state"], shock)
                self.assertEqual(pubs["elc6012/online/state"], "ON")

    def test_estado_do_bypass(self):
        pubs = self.publish("armado_bypass1")
        self.assertEqual(pubs["elc6012/zone/1/bypass"], "ON")
        self.assertEqual(pubs["elc6012/zone/2/bypass"], "OFF")
        self.assertNotIn("elc6012/zone/9/bypass", pubs)

    def test_comandos_mqtt(self):
        cases = [("elc6012/alarm/set", b"ARM_AWAY", "ARM_AWAY"),
                 ("elc6012/shock/set", b"off", "SHOCK_OFF"),
                 ("elc6012/zone/3/bypass/set", b"ON", "BYPASS_ON_3")]
        for topic, payload, expected in cases:
            self.b._on_message(None, None, FakeMsg(topic, payload))
            self.assertEqual(self.b.commands.get_nowait(), expected)

    def test_comandos_rejeitados(self):
        for msg in (FakeMsg("elc6012/zone/9/bypass/set", b"ON"),
                    FakeMsg("elc6012/alarm/set", b"ARM_HOME"),
                    FakeMsg("elc6012/alarm/set", b"DISARM", retain=True)):
            self.b._on_message(None, None, msg)
        self.assertTrue(self.b.commands.empty())

    def test_discovery(self):
        self.b._publish_discovery()
        pubs = self.b.mqtt.pubs
        configs = {t: json.loads(p) for t, p in pubs.items() if p}
        switches = [t for t in configs if t.startswith("homeassistant/switch/")]
        self.assertEqual(len(switches), 1 + c.NUM_ZONES)   # choque + bypass 1..8
        sw = configs["homeassistant/switch/elc6012/bypass_switch3/config"]
        self.assertEqual(sw["command_topic"], "elc6012/zone/3/bypass/set")
        self.assertEqual(sw["default_entity_id"], "switch.bypass_zona_3")
        # entidades antigas removidas (payload vazio retido)
        self.assertEqual(pubs["homeassistant/binary_sensor/elc6012/bypass1/config"], "")
        self.assertEqual(pubs["homeassistant/binary_sensor/elc6012/zone9/config"], "")
        self.assertNotIn("homeassistant/binary_sensor/elc6012/zone8/config",
                         [t for t, p in pubs.items() if p == ""])


if __name__ == "__main__":
    unittest.main()
