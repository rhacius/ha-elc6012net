# ELC 6012 NET

Ponte entre o eletrificador Intelbras ELC 6012 NET e o Home Assistant. O
controle passa pela nuvem Intelbras (o mesmo caminho do app Guardian), então o
ELC precisa estar online no app.

## O add-on substitui o app Guardian

Com o add-on, o uso do dia a dia é todo pelo Home Assistant: ligar/desligar o
choque, armar/desarmar o alarme, bypass de zonas, estado das zonas, histórico de
eventos — e as notificações (disparo, choque desligado, falta de energia…) vêm
de automações do HA sobre essas entidades (exemplos no README do repositório).

A nuvem Intelbras aceita **uma sessão por eletrificador** e o add-on mantém a sua
aberta — por isso, **enquanto ele roda, o app Guardian mostra "central
desconectada"**. O app só é necessário para configurações de instalação (zonas,
usuários, PGM, Wi-Fi, pulsos falhos, firmware): pare o add-on, use o app e inicie
o add-on de novo.

## Requisitos

- Add-on **Mosquitto broker** instalado e a integração **MQTT** configurada.
  As credenciais do broker são obtidas automaticamente.

## Configuração

| Opção | Descrição |
|---|---|
| `mac` | MAC do ELC (ex.: `001A3F123456`; com ou sem `:`) — aparece no app Guardian |
| `password` | Senha do ELC cadastrada no app Guardian |
| `poll` | Intervalo de consulta em segundos (10–600, padrão 15) |
| `prefix` | Prefixo dos tópicos MQTT (padrão `elc6012`) |

O add-on precisa de saída para a internet na porta TCP 9009 (nuvem Intelbras).

## Entidades

O dispositivo **ELC 6012 NET** aparece na integração MQTT com o painel de
alarme (`alarm_control_panel.cerca_eletrica`), o switch de choque, os switches
de bypass das 8 zonas, os sensores das zonas, disparo, sinal e conectividade, o
sensor "Último evento" e a entidade de eventos (`event.cerca_eletrica`, tipos
`disparo`, `panico`, `arme`, `desarme`, `bypass`, `energia`, `restauracao`,
`outro`). O disparo do choque (rompimento/aterramento da cerca) chega como
`disparo` nessa entidade, mesmo com o alarme desarmado.

## Problemas comuns

- **Log com NACK 50 / ponte OFF:** outra sessão pegou o eletrificador (app
  Guardian ou CLI). Feche-a; o add-on reconecta sozinho (backoff até 10 min).
- **Bypass recusado:** só funciona com o alarme desarmado.
- **Login código 25:** senha errada.
