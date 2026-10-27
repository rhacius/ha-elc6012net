# ELC 6012 NET

Ponte entre o eletrificador Intelbras ELC 6012 NET e o Home Assistant. O
controle passa pela nuvem Intelbras (o mesmo caminho do app Guardian), então o
ELC precisa estar online no app.

## Importante: uma sessão por painel

A nuvem Intelbras aceita **uma sessão por ELC**. O add-on mantém a sua aberta, então,
enquanto ele estiver rodando, **o app Guardian mostra "central desconectada"**.
Controle a cerca pelo Home Assistant, ou pare o add-on para usar o app.

## Requisitos

- Add-on **Mosquitto broker** instalado e a integração **MQTT** configurada.
  As credenciais do broker são obtidas automaticamente.

## Configuração

| Opção | Descrição |
|---|---|
| `mac` | MAC do ELC (ex.: `001A3F123456`) |
| `password` | Senha do ELC cadastrada no app Guardian |
| `poll` | Intervalo de consulta em segundos (10–600, padrão 15) |
| `prefix` | Prefixo dos tópicos MQTT |

## Entidades

O dispositivo **ELC 6012 NET** aparece na integração MQTT com o painel de
alarme (`alarm_control_panel.cerca_eletrica`), o switch de choque, os switches
de bypass das 8 zonas, os sensores das zonas, disparo, sinal e conectividade, o
sensor "Último evento" e a entidade de eventos (`event.cerca_eletrica`).
