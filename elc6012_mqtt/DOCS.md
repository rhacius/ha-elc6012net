# ELC 6012 NET

Ponte entre o eletrificador Intelbras ELC 6012 NET e o Home Assistant. O
controle passa pela nuvem Intelbras (o mesmo caminho do app Guardian), então o
ELC precisa estar online no app.

## Requisitos

- Add-on **Mosquitto broker** instalado e a integração **MQTT** configurada.
  As credenciais do broker são obtidas automaticamente.

## Configuração

| Opção | Descrição |
|---|---|
| `mac` | MAC do ELC (ex.: `001A3F123456`) |
| `password` | Senha do ELC cadastrada no app Guardian |
| `poll` | Intervalo de consulta em segundos (30–600; abaixo de ~30 s o relay Intelbras recusa logins) |
| `prefix` | Prefixo dos tópicos MQTT |

## Entidades

O dispositivo **ELC 6012 NET** aparece na integração MQTT com o painel de
alarme (`alarm_control_panel.cerca_eletrica`), o switch de choque, os switches
de bypass das 8 zonas, os sensores das zonas, disparo, sinal e conectividade.
