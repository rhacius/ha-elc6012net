#!/usr/bin/env python3
"""
Cliente do protocolo Intelbras ELC 6012 NET (eletrificador de cerca).

O ELC 6012 NET expõe na rede local (porta TCP 9009) APENAS um serviço de
descoberta (2 sondas: MAC e modelo). Todo o controle (status, arme, desarme)
passa pela nuvem Intelbras (TCP puro, sem TLS), que faz relay até o eletrificador:

  1. amt.intelbras.com.br:9009   -> pacote CloudPacket(0xE5, MAC...) -> 0xFD
  2. amt8000.intelbras.com.br:9009 (mesma sessão TCP para tudo):
       a. bind de app ID : Packet(0x30F6, 16 bytes [01, 00 x14, 01]) -> F0FE
       b. bind de MAC    : Packet(0xFFF0, MAC em ASCII 12 chars)     -> F0FE
       c. login          : Packet(0xF0F0, [01, senha 6B, 10, 00])    -> F0F0, erro=0
       d. status         : PacketFence(0x0B4A)                        -> 165 bytes
       e. arme/desarme   : Packet(0x401E, [partição, modo])           -> status (165 B)
                           modo: 0=desarme, 1=arme; partição 255 = alarme + choque,
                           1 = só alarme, 2 = só choque
       f. bypass         : Packet(0x401F, [255, z1..z8])              -> status (165 B)
       g. eventos        : Packet(0x3900, [página 0-7])               -> 129 B

Especificação obtida por engenharia reversa do app Guardian
(br.com.intelbras.amtremotomobile) e validada contra um ELC 6012 NET real —
ver PROTOCOLO-ELC6012NET.md.

Uso:
  # Descoberta local (rede local, sem senha):
  python3 elc6012_client.py --host IP_DO_ELC probe

  # Controle via nuvem (requer MAC + senha do eletrificador). A senha vem de
  # ELC_PASSWORD (preferível: não aparece no `ps`) ou de --password:
  export ELC_PASSWORD=SUASENHA
  python3 elc6012_client.py --mac 001A3F123456 status
  python3 elc6012_client.py --mac 001A3F123456 arm
  python3 elc6012_client.py --mac 001A3F123456 disarm
  python3 elc6012_client.py --mac 001A3F123456 shock-on    # só o choque
  python3 elc6012_client.py --mac 001A3F123456 shock-off
  python3 elc6012_client.py --mac 001A3F123456 alarm-on    # só o alarme
  python3 elc6012_client.py --mac 001A3F123456 alarm-off
  python3 elc6012_client.py --mac 001A3F123456 bypass 3    # anula a zona 3
  python3 elc6012_client.py --mac 001A3F123456 unbypass 3  # (alarme desarmado)
  python3 elc6012_client.py --mac 001A3F123456 events      # últimos 64 eventos

A nuvem aceita uma sessão por painel: com a ponte/add-on rodando, o login
recebe NACK 50 — pare-a antes de usar o CLI.
"""
import argparse
import os
import socket
import sys
import time

LOCAL_PORT = 9009
CLOUD_GENERAL = ("amt.intelbras.com.br", 9009)
CLOUD_8000 = ("amt8000.intelbras.com.br", 9009)

CMD_CLOUD_CONNECT = 0xE5      # CloudPacket: descoberta do servidor do painel
CMD_BIND_APPID = 0x30F6       # bind do ID da aplicação no relay 8000
CMD_BIND_MAC = 0xFFF0         # bind do MAC no relay 8000
CMD_LOGIN = 0xF0F0            # login na central (senha)
CMD_FENCE_STATUS = 0x0B4A     # leitura de status do eletrificador
CMD_ARM_DISARM = 0x401E       # arme/desarme [partição, modo]
CMD_BYPASS = 0x401F           # bypass [255, z1..z8] (1 byte por zona, 1 = anulada)
CMD_EVENTS = 0x3900           # buffer de eventos [página 0-7]
ACK_OK = 0xF0FE               # ACK do relay (binds)
NACK = 0xF0FD                 # NACK (erro) — payload[0] = código

PARTITION_FENCE = 255         # alarme + choque (o que o arm/disarm aciona)
PARTITION_ALARM = 1           # só alarme  (estado: [31].0)
PARTITION_SHOCK = 2           # só choque  (estado: [30].0) — botão de choque do app
STATUS_LEN = 165              # resposta do 0x0B4A (e do arme/desarme)
NUM_ZONES = 8                 # o app lê só o byte [46] de zonas (ReadFenceStatus)
MAX_FRAME = 1024              # limite de sanidade para o campo de tamanho


# ---------------------------------------------------------------------------
# Enquadramento
# ---------------------------------------------------------------------------

def checksum(data: bytes) -> int:
    """XOR de todos os bytes, complementado."""
    c = 0
    for b in data:
        c ^= b
    return c ^ 0xFF


def packet8000(cmd: int, payload: bytes = b"", marker: bytes = b"\x00\x00\x00\xf1") -> bytes:
    """Pacote estilo AMT8000: [marker 4B][len BE 2B][cmd BE 2B][payload][chk].

    marker padrão 00 00 00 F1 (isRemote=false, usado nos binds); o app usa
    00 00 00 00 quando IsRemoteConnection=true. O relay aceita ambos.
    """
    ln = len(payload) + 2
    body = marker + ln.to_bytes(2, "big") + cmd.to_bytes(2, "big") + payload
    return body + bytes([checksum(body)])


def packet_fence(cmd: int, payload: bytes = b"") -> bytes:
    """Pacote Fence: marker 00 00 8F FF (usado no status 0x0B4A)."""
    return packet8000(cmd, payload, marker=b"\x00\x00\x8f\xff")


def cloud_packet(cmd: int, data: bytes) -> bytes:
    """CloudPacket: [1+len(data)][cmd][data][chk] — usado no servidor geral."""
    body = bytes([1 + len(data), cmd]) + data
    return body + bytes([checksum(body)])


def password_bytes(password: str) -> bytes:
    """Senha do ELC: cada caractere vira um byte (Convert.ToByte(c,16)),
    completado com zeros até 6 bytes. Ex.: '1234' -> 01 02 03 04 00 00.

    Levanta ValueError para senha vazia, com mais de 6 caracteres ou com
    caractere não hexadecimal — como o app, em vez de logar com outra senha."""
    if not 1 <= len(password) <= 6:
        raise ValueError("a senha do ELC deve ter de 1 a 6 caracteres")
    try:
        out = [int(ch, 16) for ch in password]
    except ValueError:
        raise ValueError("a senha do ELC só pode conter dígitos (0-9, A-F)") from None
    return bytes(out + [0] * (6 - len(out)))


def normalize_mac(mac: str) -> str:
    """'00:1a:3f:12:34:56' / '00-1A-…' / '001A3F123456' -> '001A3F123456'."""
    m = mac.replace(":", "").replace("-", "").upper()
    if len(m) != 12 or any(c not in "0123456789ABCDEF" for c in m):
        raise ValueError(f"MAC inválido: {mac!r} (esperado 12 dígitos hex, ex.: 001A3F123456)")
    return m


def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(normalize_mac(mac))


# ---------------------------------------------------------------------------
# Sessão cloud
# ---------------------------------------------------------------------------

class PanelRefused(RuntimeError):
    """O painel recusou o comando (NACK ou pré-condição); a sessão continua válida."""


class ElcCloudSession:
    """Uma sessão TCP com o relay amt8000 (binds + login).

    O relay fecha conexões ociosas; para polling periódico, abra uma sessão
    nova por ciclo (ver Elc6012Client).
    """

    def __init__(self, mac: str, password: str, timeout: float = 15.0, verbose: bool = False):
        self.mac_str = normalize_mac(mac)
        self.mac_hex = bytes.fromhex(self.mac_str)
        self.password_bytes = password_bytes(password)
        self.timeout = timeout
        self.verbose = verbose
        self.sock: socket.socket | None = None

    def _log(self, *msg):
        if self.verbose:
            print("[elc]", *msg, file=sys.stderr)

    # -- baixo nível --

    def _xchg(self, data: bytes, timeout: float | None = None) -> bytes:
        """Envia e lê exatamente um frame de resposta.

        O relay não fecha a conexão, então o fim do frame vem do campo de
        tamanho len (BE em [4..5]), cuja regra depende do eco ([6..7]):
          - ACK/login/NACK: total = 4 (prefixo) + 2 (len) + len + 1 (checksum),
            com len incluindo os 2 bytes do comando;
          - status 0x0B4A: total = len + 1 (len=0xA4 em frames de 165 bytes);
          - eventos 0x3900: sempre 129 bytes (o len vem 0x82 — não confere).
        Lê só esses bytes — um frame seguinte fica no socket em vez de se
        misturar a este. Em timeout, devolve o que chegou (os chamadores
        rejeitam pelo eco)."""
        self._drain()
        self.sock.sendall(data)
        deadline = time.monotonic() + (timeout or self.timeout)
        buf = b""
        need = 8   # até ler o cabeçalho e o eco
        header = True
        while len(buf) < need:
            wait = deadline - time.monotonic()
            if wait <= 0:
                break
            self.sock.settimeout(wait)
            try:
                chunk = self.sock.recv(need - len(buf))
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if header and len(buf) >= 8:
                header = False
                ln = int.from_bytes(buf[4:6], "big")
                echo = self._echo(buf)
                if echo == CMD_FENCE_STATUS:
                    need = ln + 1
                elif echo == CMD_EVENTS:
                    need = EVENT_FRAME   # o len (0x82) não bate com o tamanho real
                else:
                    need = ln + 7
                if need > MAX_FRAME:
                    raise ConnectionError(f"frame com tamanho inválido ({need} B): {buf.hex(' ')}")
        if len(buf) == need and checksum(buf[:-1]) != buf[-1] and self._echo(buf) == NACK:
            # O relay não conta o código de erro no len do NACK: o que parecia o
            # checksum é o código ([8]) e o checksum real vem em seguida.
            self.sock.settimeout(1.0)
            try:
                buf += self.sock.recv(1)
            except socket.timeout:
                pass
        if len(buf) >= need and checksum(buf[:-1]) != buf[-1]:
            raise ConnectionError(f"checksum inválido na resposta: {buf.hex(' ')}")
        return buf

    def _drain(self):
        """Descarta bytes pendentes (ex.: resposta que chegou após o timeout).

        Numa sessão longa (a ponte mantém uma só), uma resposta atrasada seria
        lida como a resposta do próximo comando."""
        self.sock.setblocking(False)
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise ConnectionError("conexão fechada pelo relay")
                self._log(f"descartando {len(chunk)} B pendentes: {chunk.hex(' ')}")
        except (BlockingIOError, socket.timeout):
            pass
        finally:
            self.sock.setblocking(True)

    @staticmethod
    def _echo(resp: bytes) -> int:
        return int.from_bytes(resp[6:8], "big") if len(resp) >= 8 else -1

    # -- conexão --

    def open(self):
        """Executa a sequência completa: descoberta do servidor + binds + login."""
        # 1. servidor geral: informa qual servidor o painel usa (0xFD = amt8000)
        gs = socket.create_connection(CLOUD_GENERAL, timeout=10)
        try:
            gs.settimeout(10)
            buf = bytearray(20)
            buf[0] = 0x04
            buf[1:7] = self.mac_hex
            buf[8] = 0x01
            buf[9:15] = self.mac_hex
            gs.sendall(cloud_packet(CMD_CLOUD_CONNECT, bytes(buf)))
            resp = gs.recv(64)
        finally:
            gs.close()
        if not resp:
            raise ConnectionError("servidor geral Intelbras não respondeu")
        if resp[0] == 0xFE:
            raise ConnectionError("painel não está conectado à nuvem Intelbras")
        if resp[0] != 0xFD:
            raise ConnectionError(f"resposta inesperada do servidor geral: {resp.hex(' ')}")
        self._log("servidor geral: painel no AMT8000")

        # 2. servidor amt8000 — se algo falhar daqui em diante, o __exit__ não
        # roda (a exceção sai do __enter__): fecha o socket aqui.
        self.sock = socket.create_connection(CLOUD_8000, timeout=10)
        try:
            self._bind_and_login()
        except BaseException:
            self.close()
            raise

    def _bind_and_login(self):
        self.sock.settimeout(self.timeout)

        # 2a. bind do ID da aplicação
        appid = bytearray(16)
        appid[0] = 0x01
        appid[15] = 0x01
        resp = self._xchg(packet8000(CMD_BIND_APPID, bytes(appid)))
        if self._echo(resp) != ACK_OK:
            raise ConnectionError(f"bind appID recusado: {resp.hex(' ')}")

        # 2b. bind do MAC (associa esta conexão ao eletrificador)
        resp = self._xchg(packet8000(CMD_BIND_MAC, self.mac_str.encode()))
        if self._echo(resp) != ACK_OK:
            raise ConnectionError(f"bind MAC recusado: {resp.hex(' ')}")

        # 2c. login com a senha do eletrificador
        payload = bytes([0x01]) + self.password_bytes + bytes([0x10, 0x00])
        resp = self._xchg(packet8000(CMD_LOGIN, payload))
        if self._echo(resp) == NACK:
            # Código 50 (validado): o painel já tem outra sessão ativa — app
            # Guardian, outra ponte ou uma sessão anterior ainda não liberada.
            code = resp[8] if len(resp) > 9 else -1
            hint = " — outra sessão ativa (app Guardian?)" if code == 50 else ""
            raise ConnectionError(f"login recusado pelo relay (NACK, código {code}){hint}")
        if self._echo(resp) != CMD_LOGIN or len(resp) < 9:
            raise ConnectionError(f"login sem resposta válida: {resp.hex(' ')}")
        err = resp[8]
        if err == 25:
            raise PermissionError("senha inválida (código 25)")
        if err != 0:
            raise PermissionError(f"login recusado (código {err})")
        self._log("login OK")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- operações --

    def status(self) -> dict:
        resp = self._xchg(packet_fence(CMD_FENCE_STATUS), timeout=20.0)
        if len(resp) < STATUS_LEN or self._echo(resp) != CMD_FENCE_STATUS:
            raise RuntimeError(f"resposta de status inválida ({len(resp)} B): {resp.hex(' ')}")
        return parse_fence_status(resp)

    def arm(self, partition: int = PARTITION_FENCE) -> dict:
        """Arma o eletrificador. A resposta já é o novo status."""
        resp = self._xchg(packet8000(CMD_ARM_DISARM, bytes([partition, 1])))
        return self._check_cmd(self._confirm(resp))

    def disarm(self, partition: int = PARTITION_FENCE) -> dict:
        """Desarma o eletrificador. A resposta já é o novo status."""
        resp = self._xchg(packet8000(CMD_ARM_DISARM, bytes([partition, 0])))
        return self._check_cmd(self._confirm(resp))

    def _confirm(self, resp: bytes) -> bytes:
        """Sem resposta ao comando, consulta o status na mesma sessão.

        Observado (27/out/2026): o painel aplicou o 0x401E mas a resposta não
        chegou. O status — ou a resposta atrasada, que também é um status —
        mostra o estado real; quem chamou confere se o comando pegou."""
        if resp:
            return resp
        self._log("sem resposta ao comando; consultando o status")
        return self._xchg(packet_fence(CMD_FENCE_STATUS), timeout=20.0)

    def set_shock(self, on: bool) -> dict:
        """Liga/desliga só o choque (partição 2), sem mexer no alarme."""
        return self.arm(PARTITION_SHOCK) if on else self.disarm(PARTITION_SHOCK)

    def set_alarm(self, on: bool) -> dict:
        """Arma/desarma só o alarme (partição 1), sem mexer no choque."""
        return self.arm(PARTITION_ALARM) if on else self.disarm(PARTITION_ALARM)

    def events(self) -> list[dict]:
        """Lê o buffer de eventos do painel: 8 páginas (0x3900 [0..7]).

        Como o app (GeneralEventsElc6012NetDataSource): pacote com marker
        00 00 00 00, resposta com eco 0x3900. Página 0 = eventos mais novos;
        a lista volta do mais novo para o mais antigo (validado ao vivo).

        Cada login na nuvem grava um "Acesso por download" (1410) no buffer
        de 64 eventos."""
        return [ev for page in range(EVENT_PAGES) for ev in self.events_page(page)]

    def events_page(self, page: int) -> list[dict]:
        """Uma página (8 eventos) do buffer; a 0 tem os mais novos."""
        resp = self._xchg(packet8000(CMD_EVENTS, bytes([page]), marker=b"\x00\x00\x00\x00"),
                          timeout=20.0)
        if self._echo(resp) != CMD_EVENTS:
            raise RuntimeError(f"resposta inválida na página {page} de eventos: {resp.hex(' ')}")
        self._log(f"eventos página {page}: {resp.hex(' ')}")
        evs = parse_events(resp)
        for ev in evs:
            ev["pagina"] = page
        return evs

    def set_bypass(self, zone: int, on: bool) -> dict:
        """Anula (on=True) ou reativa uma zona. A resposta já é o novo status.

        O 0x401F define o bypass de TODAS as zonas de uma vez, então lê o
        status antes para preservar as demais. O painel só aceita com o
        alarme desarmado — verificado aqui para dar um erro claro."""
        if not 1 <= zone <= NUM_ZONES:
            raise ValueError(f"zona deve ser de 1 a {NUM_ZONES}")
        st = self.status()
        if st["sistema_armado"]:
            raise PanelRefused("desarme o alarme antes de anular/reativar zonas")
        zones = set(st["zonas_bypass"])
        if on:
            zones.add(zone)
        else:
            zones.discard(zone)
        payload = bytes([PARTITION_FENCE] + [int(z in zones) for z in range(1, NUM_ZONES + 1)])
        resp = self._xchg(packet8000(CMD_BYPASS, payload))
        return self._check_cmd(self._confirm(resp))

    def _check_cmd(self, resp: bytes) -> dict:
        echo = self._echo(resp)
        if echo == NACK:
            code = resp[8] if len(resp) > 9 else -1
            raise PanelRefused(f"comando recusado pelo painel (NACK, código {code})")
        if echo == CMD_FENCE_STATUS and len(resp) >= STATUS_LEN:
            return parse_fence_status(resp)
        if not resp:
            # Nem o comando nem o status de confirmação responderam.
            raise TimeoutError("painel não respondeu ao comando (estado incerto — consulte o status)")
        raise RuntimeError(f"resposta inesperada: {resp.hex(' ')}")


# ---------------------------------------------------------------------------
# Fachada de alto nível (uma sessão por operação — robusto para polling)
# ---------------------------------------------------------------------------

class Elc6012Client:
    def __init__(self, mac: str, password: str, verbose: bool = False):
        self.mac = mac
        self.password = password
        self.verbose = verbose

    def status(self) -> dict:
        with ElcCloudSession(self.mac, self.password, verbose=self.verbose) as s:
            return s.status()

    def arm(self) -> dict:
        with ElcCloudSession(self.mac, self.password, verbose=self.verbose) as s:
            return s.arm()

    def disarm(self) -> dict:
        with ElcCloudSession(self.mac, self.password, verbose=self.verbose) as s:
            return s.disarm()

    def set_shock(self, on: bool) -> dict:
        with ElcCloudSession(self.mac, self.password, verbose=self.verbose) as s:
            return s.set_shock(on)

    def set_alarm(self, on: bool) -> dict:
        with ElcCloudSession(self.mac, self.password, verbose=self.verbose) as s:
            return s.set_alarm(on)

    def set_bypass(self, zone: int, on: bool) -> dict:
        with ElcCloudSession(self.mac, self.password, verbose=self.verbose) as s:
            return s.set_bypass(zone, on)

    def events(self) -> list[dict]:
        with ElcCloudSession(self.mac, self.password, verbose=self.verbose) as s:
            return s.events()


# ---------------------------------------------------------------------------
# Descoberta local (porta 9009 do ELC — somente sondas, sem controle)
# ---------------------------------------------------------------------------

def discover_local(host: str, port: int = LOCAL_PORT, timeout: float = 4.0) -> tuple[str, int]:
    """Sondas de descoberta do ELC na rede local.

    Retorna (mac 'XX:XX:XX:XX:XX:XX', modelo_byte).
    O ELC aceita uma sonda por conexão TCP.
    """
    def probe(data: bytes) -> bytes:
        s = socket.create_connection((host, port), timeout=timeout)
        try:
            s.settimeout(timeout)
            s.sendall(data)
            return s.recv(64)
        finally:
            s.close()

    mac_resp = probe(bytes([0x01, 0xC4, 0x3A]))
    if len(mac_resp) < 8 or mac_resp[1] != 0xC4:
        raise ConnectionError(f"sonda MAC falhou: {mac_resp.hex(' ') if mac_resp else '(vazio)'}")
    mac = ":".join(f"{b:02X}" for b in mac_resp[2:8])

    model_resp = probe(bytes([0x01, 0xC2, 0x3C]))
    model = model_resp[2] if len(model_resp) >= 3 and model_resp[1] == 0xC2 else -1
    return mac, model


# ---------------------------------------------------------------------------
# Eventos (ElcInterpreterInformation.ReadEventsData, validado ao vivo)
# ---------------------------------------------------------------------------

EVENT_PAGES = 8
EVENT_RECORD = 15     # bytes por registro; 8 registros por página, a partir de [8]
EVENT_END = 128       # o app lê registros enquanto o início for < 128
EVENT_FRAME = 129     # 8 (cabeçalho) + 8 x 15 + 1 (checksum)

# Códigos Contact ID do ELC (Elc6012Net.EVENTS_TRANSLATED). Um dígito por byte,
# com 0 escrito como A; chave com 4 dígitos (qualificador + evento) e, na falta
# dela, só os 3 do evento. Nomes traduzidos das chaves de recurso do app.
EVENT_NAMES = {
    "4A1": "Arme/desarme por usuário", "14A1": "Desarme por usuário", "34A1": "Arme por usuário",
    "4A7": "Arme/desarme remoto", "14A7": "Desarme remoto", "34A7": "Arme remoto",
    "4A3": "Arme/desarme automático", "14A3": "Arme automático", "34A3": "Desarme automático",
    "456": "Arme stay", "1456": "Desarme stay", "3456": "Arme stay",
    "57A": "Bypass de zona", "13A": "Disparo de zona", "133": "Disparo de zona 24h",
    # Perímetro (Contact ID 131): disparo do choque — rompimento/aterramento da
    # cerca após N pulsos falhos. Fora do dicionário do app, que só o trata
    # como partição de choque (1131 na partição 1); nome conforme o manual.
    "131": "Disparo do choque (cerca)",
    "12A": "Pânico audível", "122": "Pânico silencioso", "146": "Pânico silencioso",
    "384": "Bateria baixa de sensor", "3A1": "Falta de energia elétrica (AC)",
    "342": "Falha de AC no módulo de expansão", "145": "Tamper do módulo de expansão",
    "422": "Acionamento de PGM", "3A6": "Alteração de programação", "41A": "Acesso por download",
    "3A5": "Reset do sistema", "461": "Senha incorreta", "6A1": "Teste manual",
    "6A2": "Teste periódico", "621": "Reset do buffer de eventos", "625": "Reset de data/hora",
    "616": "Solicitação de manutenção", "354": "Falha ao reportar evento", "4A8": "Arme rápido",
}
EVENT_PARTITIONS = {0: "—", 1: "alarme", 2: "choque", 15: "alarme e choque"}


def parse_events(resp: bytes) -> list[dict]:
    """Registros de uma página de eventos (resposta do 0x3900).

    Registro de 15 bytes: [0..3] dígitos Contact ID, [5] partição,
    [7..8] zona/usuário, [9..11] dia/mês/ano, [12..14] hora/min/seg.
    Registro começando com FF = vazio."""
    events = []
    for i in range(8, min(EVENT_END, len(resp) - 1), EVENT_RECORD):
        rec = resp[i:i + EVENT_RECORD]
        if len(rec) < EVENT_RECORD or rec[0] == 0xFF:
            continue
        digits = "".join(f"{d:X}" for d in rec[:4])
        full, short = digits.lstrip("0") or "0", f"{rec[1]:X}{rec[2]:X}{rec[3]:X}"
        name = EVENT_NAMES.get(full) or EVENT_NAMES.get(short)
        if name and full not in EVENT_NAMES and rec[0] == 3:
            name += " (restauração)"
        partition = rec[5]
        # O app trata 1131 (perímetro) na partição 1 como choque; aplicado
        # também à restauração (3131).
        if partition == 1 and digits[1:] == "131":
            partition = 2
        events.append({
            "codigo": digits.replace("A", "0"),   # Contact ID legível, ex.: 1130
            "evento": name or f"Evento {digits.replace('A', '0')}",
            "particao": EVENT_PARTITIONS.get(partition, str(partition)),
            "zona_usuario": f"{rec[7]}{rec[8]}",
            "data": f"{rec[9]:02d}/{rec[10]:02d}/{rec[11]:02d}",
            "hora": f"{rec[12]:02d}:{rec[13]:02d}:{rec[14]:02d}",
            "bruto": rec.hex(" "),
        })
    return events


# ---------------------------------------------------------------------------
# Interpretação do status (OnlineInterpreter.ReadFenceStatus, validado ao vivo)
# ---------------------------------------------------------------------------

def parse_fence_status(resp: bytes) -> dict:
    """Interpreta a resposta de 165 bytes do comando 0x0B4A (ou do arme/desarme).

    Offsets relativos ao início do frame (inclui os 4 bytes de marker):
      [6..7]   eco do comando (0x0B4A)
      [8]      modelo (0x35 = ELC 6012 NET)
      [30].0   CHOQUE (alta tensão ativa na cerca; independe do alarme —
               "desarmado com choque" = [30]=0x81 [31]=0x80, validado)
      [31].0   ALARME armado (o app mostra "armado" = [30].0 AND [31].0)
      [46..47] bitmask LE de zonas abertas (1-16)
      [54..55] bitmask de zonas disparadas
      [62..63] bitmask de zonas em bypass
      [72..77] dia, mês, ano, hora, min, seg (relógio do painel)
      [163]    sinal (<=37 -> 100%; senão 174-2*v)
      [164]    checksum
    """
    def bit(b: int, n: int) -> bool:
        return bool(resp[b] & (1 << n)) if len(resp) > b else False

    def mask16(off: int) -> int:
        return (resp[off] | (resp[off + 1] << 8)) if len(resp) >= off + 2 else 0

    sig = resp[163] if len(resp) > 163 else None
    dt = None
    if len(resp) > 77 and 1 <= resp[72] <= 31 and 1 <= resp[73] <= 12:
        dt = {"dia": resp[72], "mes": resp[73], "ano": resp[74],
              "hora": resp[75], "min": resp[76], "seg": resp[77]}

    choque = bit(30, 0)
    sistema_armado = bit(31, 0)
    return {
        "armado": choque and sistema_armado,   # mesma regra do app
        "choque": choque,
        "sistema_armado": sistema_armado,
        "stay": bit(31, 1),
        "zonas_abertas": [i + 1 for i in range(16) if mask16(46) & (1 << i)],
        "zonas_disparadas": [i + 1 for i in range(16) if mask16(54) & (1 << i)],
        "zonas_bypass": [i + 1 for i in range(16) if mask16(62) & (1 << i)],
        "data_hora": dt,
        "sinal_pct": (100 if sig <= 37 else max(0, 174 - 2 * sig)) if sig is not None else None,
        "modelo": resp[8] if len(resp) > 8 else None,
        "bruto_hex": resp.hex(" "),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_status(st: dict):
    print(f"Armado            : {'SIM' if st['armado'] else 'NÃO'}")
    print(f"Choque na cerca   : {'SIM' if st['choque'] else 'NÃO'}")
    print(f"Zonas abertas     : {st['zonas_abertas']}")
    print(f"Zonas disparadas  : {st['zonas_disparadas']}")
    print(f"Zonas bypass      : {st['zonas_bypass']}")
    if st["data_hora"]:
        d = st["data_hora"]
        print(f"Relógio do painel : {d['dia']:02d}/{d['mes']:02d}/{d['ano']:02d} "
              f"{d['hora']:02d}:{d['min']:02d}:{d['seg']:02d}")
    if st["sinal_pct"] is not None:
        print(f"Sinal             : {st['sinal_pct']}%")


def main():
    ap = argparse.ArgumentParser(description="Cliente ELC 6012 NET (protocolo Guardian)")
    ap.add_argument("--host", help="IP do ELC na rede local (só para 'probe')")
    ap.add_argument("--mac", default="", help="MAC do ELC (ex.: 001A3F123456)")
    ap.add_argument("--password", default=os.environ.get("ELC_PASSWORD", ""),
                    help="senha do eletrificador (padrão: variável ELC_PASSWORD)")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("comando", choices=["probe", "status", "arm", "disarm", "shock-on", "shock-off",
                                           "alarm-on", "alarm-off", "bypass", "unbypass",
                                           "events"])
    ap.add_argument("zona", nargs="?", type=int,
                    help=f"zona (1-{NUM_ZONES}) para bypass/unbypass")
    ns = ap.parse_args()
    if ns.comando in ("bypass", "unbypass") and not (ns.zona and 1 <= ns.zona <= NUM_ZONES):
        ap.error(f"{ns.comando} precisa da zona (1-{NUM_ZONES}), ex.: bypass 3")

    if ns.comando == "probe":
        if not ns.host:
            ap.error("probe precisa do IP do ELC: --host IP_DO_ELC")
        mac, model = discover_local(ns.host)
        print(f"MAC    : {mac}")
        print(f"Modelo : 0x{model:02X} ({'ELC 6012 NET' if model == 0x35 else 'desconhecido'})")
        print("(controle é feito via nuvem — use --mac e --password)")
        return

    if not ns.mac:
        ap.error("comandos de controle precisam de --mac (descubra com 'probe')")
    if not ns.password:
        ap.error("comandos de controle precisam da senha do app Guardian "
                 "(variável ELC_PASSWORD ou --password)")
    try:
        normalize_mac(ns.mac)
        password_bytes(ns.password)
    except ValueError as e:
        ap.error(str(e))

    cli = Elc6012Client(ns.mac, ns.password, verbose=ns.verbose)
    if ns.comando == "status":
        st = cli.status()
        print_status(st)
        if ns.verbose:
            print(f"Bruto             : {st['bruto_hex']}")
    elif ns.comando == "arm":
        st = cli.arm()
        print("ARMADO — cerca energizada" if st["armado"] else "FALHA: painel não confirmou o arme")
    elif ns.comando == "disarm":
        st = cli.disarm()
        print("DESARMADO — cerca desenergizada" if not st["armado"] else "FALHA: painel não confirmou o desarme")
    elif ns.comando in ("shock-on", "shock-off"):
        on = ns.comando == "shock-on"
        st = cli.set_shock(on)
        ok = st["choque"] == on
        print(("CHOQUE " + ("LIGADO" if on else "DESLIGADO")) if ok
              else "FALHA: painel não confirmou o choque")
        print(f"Alarme armado     : {'SIM' if st['sistema_armado'] else 'NÃO'}")
    elif ns.comando in ("alarm-on", "alarm-off"):
        on = ns.comando == "alarm-on"
        st = cli.set_alarm(on)
        ok = st["sistema_armado"] == on
        print(("ALARME " + ("ARMADO" if on else "DESARMADO")) if ok
              else "FALHA: painel não confirmou o alarme")
        print(f"Choque na cerca   : {'SIM' if st['choque'] else 'NÃO'}")
    elif ns.comando == "events":
        evs = cli.events()
        for ev in evs:
            print(f"{ev['data']} {ev['hora']}  {ev['evento']:<34} {ev['particao']:<16} "
                  f"zona/usuário {ev['zona_usuario']:<4} [{ev['codigo']}] pág {ev['pagina']}")
            if ns.verbose:
                print(f"    {ev['bruto']}")
        print(f"{len(evs)} evento(s)")
        return
    elif ns.comando in ("bypass", "unbypass"):
        on = ns.comando == "bypass"
        st = cli.set_bypass(ns.zona, on)
        ok = (ns.zona in st["zonas_bypass"]) == on
        print((f"ZONA {ns.zona} " + ("ANULADA" if on else "REATIVADA")) if ok
              else "FALHA: painel não confirmou o bypass")
        print(f"Zonas bypass      : {st['zonas_bypass']}")
    if ns.verbose and ns.comando != "status":
        print(f"Bruto             : {st['bruto_hex']}")


if __name__ == "__main__":
    main()
