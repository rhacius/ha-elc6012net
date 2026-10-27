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

> **Aviso:** projeto independente, sem vínculo com a Intelbras. O protocolo foi
> obtido por engenharia reversa do app Guardian para fins de interoperabilidade
> e pode mudar sem aviso. Ele controla uma cerca elétrica real — use por sua
> conta e risco.

## Instalação como add-on (Home Assistant OS / Supervised)

[![Adicionar repositório ao Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Frhacius%2Fha-elc6012net)

1. Configurações → Add-ons → Loja → ⋮ → **Repositórios** → adicione
   `https://github.com/rhacius/ha-elc6012net` (ou use o botão acima).
2. Instale o add-on **ELC 6012 NET** (imagem pronta para `aarch64` e `amd64`).
3. Na aba **Configuração**, informe o `mac` do ELC e a `password` do app Guardian.
4. Inicie. O dispositivo aparece na integração **MQTT** (requer o add-on
   Mosquitto; as credenciais do broker são obtidas automaticamente).

As seções abaixo descrevem o uso sem add-on (CLI e ponte standalone).

## Arquivos

| Arquivo | Função |
|---|---|
| `PROTOCOLO-ELC6012NET.md` | Especificação do protocolo (engenharia reversa + validação ao vivo) |
| `elc6012_client.py` | Biblioteca/CLI (stdlib pura) — teste antes de tudo! |
| `elc6012_ha_mqtt.py` | Ponte MQTT com auto-descoberta para o HA |
| `elc6012_mqtt/` | Add-on do HA (os dois `.py` da raiz são links para o código daqui) |
| `repository.yaml` | Torna o repositório instalável pela loja de add-ons |
| `tests/` | Testes com respostas reais do ELC (`python3 -m unittest`) |
| `crc_table_2018.txt` | Tabela CRC do formato 2018 (referência; o ELC não usa na nuvem) |

## 1. Descobrir o MAC e testar

```bash
pip3 install -r requirements.txt   # só a ponte precisa; o cliente é stdlib pura

# Descoberta local (o ELC deve estar na mesma rede):
python3 elc6012_client.py --host IP_DO_ELC probe
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
python3 elc6012_client.py --mac 001A3F123456 events        # histórico: últimos 64 eventos, mais novo primeiro
```

O `status` imprime os campos interpretados; `arm`/`disarm` já retornam o novo
estado confirmado pelo painel.

## 2. Rodar a ponte MQTT

```bash
export ELC_PASSWORD=SUASENHA MQTT_PASSWORD=SENHA_MQTT
python3 elc6012_ha_mqtt.py --mac 001A3F123456 \
    --mqtt IP_DO_BROKER --mqtt-user USUARIO --poll 15
```

Comandos vindos do HA (arme/desarme, choque, bypass) entram numa fila e são
executados pelo mesmo loop do polling, uma sessão cloud por vez. Comandos
publicados com *retain* são ignorados. Se um comando falhar (ex.:
NACK do painel), a ponte não fica indisponível: ela registra o erro e faz um
poll imediato para ressincronizar o estado.

> **Uma sessão por painel:** o relay Intelbras aceita só uma sessão por ELC. A
> ponte mantém a sua aberta (um login só; cada consulta leva ~0,3 s), então,
> **enquanto ela estiver rodando, o app Guardian mostra "central desconectada"**
> e o CLI recebe NACK 50 — use o HA para controlar a cerca, ou pare a ponte para
> usar o app. Se a sessão cair, a ponte reconecta com backoff (2x, até 10 min).
> Manter uma sessão também preserva o histórico: cada login grava "Acesso por
> download" no buffer de 64 eventos do ELC.

Entidades criadas no HA (descoberta automática, dispositivo "ELC 6012 NET").
Os entity_ids abaixo são sugeridos via `default_entity_id` (HA 2025.10+) e só
valem na criação da entidade; versões anteriores prefixam o nome do
dispositivo (ex.: `alarm_control_panel.elc_6012_net_cerca_eletrica`):

- **`alarm_control_panel.cerca_eletrica`** — ARMAR (away) / DESARMAR (único modo
  oferecido no HA); estado `triggered` quando houver zona disparada.
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
- **`sensor.ultimo_evento_cerca`** — último evento do painel (ex.: "Desarme remoto ·
  choque"), com data, hora, partição e zona/usuário nos atributos
- **`event.cerca_eletrica`** — dispara a cada evento novo do painel, com tipo
  `disparo`, `panico`, `arme`, `desarme`, `bypass`, `energia` ou `outro` (para
  automações; pega até um disparo curto entre duas consultas)
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
    --mac 001A3F123456 --mqtt 127.0.0.1 --poll 15
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
automaticamente.

### Dashboard de exemplo

Uma view no layout de seções com tudo o que a ponte expõe. Para usar: no
dashboard, **Editar → Adicionar view → ⋮ → Editar em YAML** e cole o trecho.

```
┌─ Cerca elétrica ──── ● Ponte  ▂▄▆ 44% ┐  ┌─ Zonas da cerca ─────────────────┐
│  [ teclado: ARMAR / DESARMAR ]        │  │  Zona 1  Zona 2  Zona 3  Zona 4  │
│  ⚡ Choque — segure para alterar  ON  │  │  Zona 5  Zona 6  Zona 7  Zona 8  │
│  🛡 Disparo da cerca          Seguro  │  │  Bypass — segure para alterar    │
│  🕘 Último evento   Desarme · choque  │  │  Zona 1  Zona 2  …       Zona 8  │
└───────────────────────────────────────┘  └──────────────────────────────────┘
```

Os comandos que mexem na cerca (choque e bypass) só disparam **segurando** o
tile e confirmando — um toque abre os detalhes. Isso evita energizar a cerca ou
anular uma zona por engano.

```yaml
title: Cerca elétrica
path: cerca
icon: mdi:fence-electric
type: sections
max_columns: 2
sections:
  - type: grid
    cards:
      - type: heading
        heading: Cerca elétrica
        icon: mdi:fence-electric
        badges:
          - type: entity
            entity: binary_sensor.ponte_elc   # ponte conectada?
          - type: entity
            entity: sensor.sinal_elc          # sinal do ELC (%)
      # ARMAR/DESARMAR aciona alarme + choque juntos
      - type: alarm-panel
        entity: alarm_control_panel.cerca_eletrica
        name: Alarme + choque
        states:
          - arm_away
      # Só o choque (o alarme não muda); segure para alternar
      - type: tile
        entity: switch.choque
        name: Choque — segure para alterar
        icon: mdi:flash
        color: red
        tap_action:
          action: more-info
        hold_action:
          action: perform-action
          perform_action: switch.toggle
          target:
            entity_id: switch.choque
          confirmation:
            text: Confirmar alteração do choque da cerca?
      - type: tile
        entity: binary_sensor.disparo
        name: Disparo da cerca
        color: red
      # Último evento do histórico do painel (arme, desarme, disparo…)
      - type: tile
        entity: sensor.ultimo_evento_cerca
        name: Último evento
        icon: mdi:history

  - type: grid
    cards:
      - type: heading
        heading: Zonas da cerca
        icon: mdi:fence
      # Uma tile por zona (aberta/fechada) — repita para as zonas 3 a 8
      - type: tile
        entity: binary_sensor.zona_1
        name: Zona 1
        vertical: true
        grid_options:
          columns: 3
      - type: tile
        entity: binary_sensor.zona_2
        name: Zona 2
        vertical: true
        grid_options:
          columns: 3
      - type: heading
        heading: Bypass — segure para anular/reativar (só com o alarme desarmado)
        heading_style: subtitle
      # Uma tile de bypass por zona — repita para as zonas 2 a 8
      - type: tile
        entity: switch.bypass_zona_1
        name: Zona 1
        icon: mdi:shield-off-outline
        color: amber
        vertical: true
        grid_options:
          columns: 3
        tap_action:
          action: more-info
        hold_action:
          action: perform-action
          perform_action: switch.toggle
          target:
            entity_id: switch.bypass_zona_1
          confirmation:
            text: Confirmar bypass da zona 1 da cerca?
```

Se o ELC usa menos zonas, basta não incluir as tiles das zonas sem fio ligado.

### Automação de exemplo

```yaml
automation:
  - alias: Desarma a cerca quando alguém chega em casa
    trigger:
      platform: state
      entity_id: person.fulano
      to: "home"
    action:
      service: alarm_control_panel.alarm_disarm
      target:
        entity_id: alarm_control_panel.cerca_eletrica
```

## 4. O protocolo em 7 linhas

1. `amt.intelbras.com.br:9009`: `CloudPacket(0xE5, [04,MAC,00,01,MAC,00x5])` → `FD`;
2. `amt8000.intelbras.com.br:9009`: bind appID `0x30F6` → `F0FE`; bind MAC `0xFFF0` → `F0FE`;
3. login `0xF0F0` `[01, senha6, 10 00]` (senha: 1 dígito = 1 byte hex) → erro 0;
4. status `0x0B4A` (marker `00 00 8F FF`) → 165 B (`[30].0`=choque, `[31].0`=alarme,
   `[62]`=zonas em bypass);
5. arme/desarme `0x401E` `[partição, modo]` (modo 1/0; partição 255 = alarme + choque,
   1 = só alarme, 2 = só choque) → novo status;
6. bypass `0x401F` `[255, z1..z8]` (1 byte por zona; define todas de uma vez) → novo status;
7. checksum = XOR de todos os bytes `^ 0xFF`.

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
| NACK código 33 (0x21) | partição inexistente ou sem login | partições válidas: 255, 1 e 2 (o cliente já usa as certas) |
| login NACK código 50 | outra sessão ativa no painel (a ponte, o app Guardian ou uma sessão anterior ainda não liberada) | pare a ponte para usar o CLI/app; após fechar uma sessão, aguarde alguns segundos |
| `bypass` recusado | alarme armado | desarme o alarme antes de anular/reativar zonas |
| Ponte OFF com NACK 50 no log | o app Guardian (ou o CLI) pegou a sessão | feche o app/CLI; a ponte reconecta sozinha |
| Tudo "unavailable" de repente | ponte morreu sem LWT | já tratado: a ponte registra LWT (will) no broker |
| App Guardian: "central desconectada" | a ponte está com a sessão | esperado — use o HA, ou pare a ponte |
