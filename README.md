# Integração Home Assistant — Intelbras ELC 6012 NET

Ponte entre o eletrificador **ELC 6012 NET** e o Home Assistant via
**MQTT com auto-descoberta** (não requer componente custom).

```
elc6012_ha_mqtt.py ──HTTPS/TCP──> nuvem Intelbras (relay amt8000) ──> ELC 6012 NET
        │
        └──MQTT──> Broker ──> Home Assistant (alarm_control_panel, zonas, sensores)
```

> **Como funciona:** o ELC 6012 NET só expõe na rede local um serviço de
> *descoberta* (porta 9009: MAC e modelo). Todo o controle (status/arme/desarme)
> passa pela **nuvem Intelbras** — o mesmo caminho do app Guardian. Portanto a
> ponte precisa de acesso à internet, do **MAC** do ELC e da **senha** cadastrada
> no app Guardian. Detalhes do protocolo: `PROTOCOLO-ELC6012NET.md`.

## Arquivos

| Arquivo | Função |
|---|---|
| `PROTOCOLO-ELC6012NET.md` | Especificação do protocolo (engenharia reversa + validação ao vivo) |
| `elc6012_client.py` | Biblioteca/CLI (stdlib pura) — teste antes de tudo! |
| `elc6012_ha_mqtt.py` | Ponte MQTT com auto-descoberta para o HA |
| `crc_table_2018.txt` | Tabela CRC do formato 2018 (referência; o ELC não usa na nuvem) |

## 1. Descobrir o MAC e testar

```bash
pip3 install -r requirements.txt   # só a ponte precisa; o cliente é stdlib pura

# Descoberta local (o ELC deve estar na mesma rede):
python3 elc6012_client.py --host 192.168.3.235 probe
#   -> MAC: 00:1A:3F:12:34:56   Modelo: 0x35 (ELC 6012 NET)

# Controle via nuvem (MAC sem ':' e a senha do app Guardian). A senha vai por
# variável de ambiente para não aparecer no `ps` (--password também funciona):
export ELC_PASSWORD=SUASENHA
python3 elc6012_client.py --mac 001A3F123456 status
python3 elc6012_client.py --mac 001A3F123456 arm
python3 elc6012_client.py --mac 001A3F123456 disarm
python3 elc6012_client.py --mac 001A3F123456 shock-on    # só o choque
python3 elc6012_client.py --mac 001A3F123456 shock-off
python3 elc6012_client.py --mac 001A3F123456 bypass 3      # anula a zona 3
python3 elc6012_client.py --mac 001A3F123456 unbypass 3    # (só com o alarme desarmado)
```

O `status` imprime os campos interpretados; `arm`/`disarm` já retornam o novo
estado confirmado pelo painel.

## 2. Rodar a ponte MQTT

```bash
export ELC_PASSWORD=SUASENHA MQTT_PASSWORD=SENHA_MQTT
python3 elc6012_ha_mqtt.py --mac 001A3F123456 \
    --mqtt IP_DO_BROKER --mqtt-user USUARIO --poll 60
```

Comandos de arme/desarme vindos do HA entram numa fila e são executados pelo
mesmo loop do polling, uma sessão cloud por vez. Comandos publicados com
*retain* no tópico `elc6012/alarm/set` são ignorados. Se um comando falhar (ex.:
NACK do painel), a ponte não fica indisponível: ela registra o erro e faz um
poll imediato para ressincronizar o estado.

> **Rate limiting:** o relay Intelbras limita sessões por minuto — polling abaixo
> de ~30 s faz o login ser recusado temporariamente. A ponte já aplica backoff
> automático (dobra o intervalo em caso de falha, até 10 min). Cada ciclo de
> polling leva ~3 s (sessão nova: descoberta + binds + login + status).

Entidades criadas no HA (descoberta automática, dispositivo "ELC 6012 NET").
Os entity_ids abaixo são sugeridos via `default_entity_id` (HA 2025.10+) e só
valem na criação da entidade; versões anteriores prefixam o nome do
dispositivo (ex.: `alarm_control_panel.elc_6012_net_cerca_eletrica`):

- **`alarm_control_panel.cerca_eletrica`** — ARMAR (away) / DESARMAR (único modo
  oferecido no HA);
  estado `triggered` quando houver zona disparada
  O estado segue **só o alarme** (o alarme pode estar armado com o choque
  desligado). ARMAR/DESARMAR aqui aciona alarme **e** choque juntos (partição 255).
- **`switch.choque`** — liga/desliga **só o choque** (o alarme não muda), como o
  botão de choque do app Guardian
- **`binary_sensor.zona_1..8`** — zonas abertas (device_class `opening`; o ELC tem 8 zonas)
- **`switch.bypass_zona_1..8`** — anula/reativa a zona (bypass). Só com o alarme
  desarmado: com ele armado o comando é recusado e o switch volta ao estado real
- **`binary_sensor.disparo`** — qualquer zona disparada
- **`binary_sensor.choque_na_cerca`** — alta tensão ativa
- **`sensor.sinal_elc`** — nível de sinal (%)
- **`binary_sensor.ponte_elc`** — conectividade da ponte; quando `OFF`, todas as
  demais entidades ficam `unavailable` (não exibem valores antigos)

### Serviço systemd (opcional)

```ini
# /etc/systemd/system/elc6012-mqtt.service
[Unit]
Description=Ponte ELC 6012 NET -> MQTT (Home Assistant)
After=network-online.target

[Service]
# ELC_PASSWORD=... e MQTT_PASSWORD=... (chmod 600, dono root)
EnvironmentFile=/etc/elc6012/credenciais.env
ExecStart=/usr/bin/python3 /opt/elc6012/elc6012_ha_mqtt.py \
    --mac 001A3F123456 --mqtt 127.0.0.1 --poll 60
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now elc6012-mqtt
```

## 3. Home Assistant

Basta a integração **MQTT** ativa e o broker acessível. As entidades aparecem
automaticamente. Exemplo de automação:

```yaml
automation:
  - alias: Desarma a cerca quando alguém chega em casa
    trigger:
      platform: state
      entity_id: person.rhacius
      to: "home"
    action:
      service: alarm_control_panel.alarm_disarm
      target:
        entity_id: alarm_control_panel.cerca_eletrica
```

## 4. O protocolo em 6 linhas

1. `amt.intelbras.com.br:9009`: `CloudPacket(0xE5, [04,MAC,00,01,MAC,00x5])` → `FD`;
2. `amt8000.intelbras.com.br:9009`: bind appID `0x30F6` → `F0FE`; bind MAC `0xFFF0` → `F0FE`;
3. login `0xF0F0` `[01, senha6, 10 00]` (senha: 1 dígito = 1 byte hex) → erro 0;
4. status `0x0B4A` (marker `00 00 8F FF`) → 165 B (`[30].0`=choque, `[31].0`=armado);
5. arme/desarme `0x401E` `[255, modo]` (modo 1/0) → novo status;
6. checksum = XOR de todos os bytes `^ 0xFF`.

## 5. Testes

```bash
python3 -m unittest -v        # na raiz do projeto
```

Usam respostas reais do ELC (`tests/frames.py`, com o MAC trocado por um
fictício) e sockets simulados — não acessam a nuvem nem o painel. Os testes da
ponte exigem o `paho-mqtt` (sem ele são pulados).

## 6. Solução de problemas

| Sintoma | Causa provável | Ação |
|---|---|---|
| `probe` sem resposta | IP errado / fora da LAN | `nc -vz <ip> 9009` |
| "painel não está conectado à nuvem" | ELC offline no relay | verificar internet do ELC no app Guardian |
| login código 25 | senha errada | usar a senha do app Guardian |
| NACK código 33 (0x21) | partição errada | o ELC usa partição **255** (já é o padrão) |
| Estado OFF/unavailable intermitente | relay fecha conexão ociosa | normal — a ponte abre sessão nova a cada ciclo |
| Tudo "unavailable" de repente | ponte morreu sem LWT | já tratado: a ponte registra LWT (will) no broker |
| Conflito com o app no celular | relay pode priorizar uma sessão | feche o app Guardian se notar falhas de comando |
