# Changelog

## 1.1.2

- **"Último evento" não fica mais vazio ao iniciar:** quando os eventos mais
  recentes do eletrificador são só "Acesso por download" (cada login grava um),
  o add-on procura nas páginas anteriores do histórico o último evento real.

## 1.1.1

- **Disparo do choque reconhecido:** o rompimento ou aterramento da cerca (evento
  Contact ID 131) agora gera o tipo `disparo` em `event.cerca_eletrica` — acontece
  mesmo com o alarme desarmado, só com o choque ligado.
- Restaurações (choque/zona restaurados, volta da energia) ganham o tipo
  `restauracao`, em vez de repetir o evento original.

## 1.1.0

- **Sessão única com a nuvem Intelbras:** um login só, consultas a cada 15 s
  (~0,3 s cada) em vez de uma sessão nova a cada 60 s.
- O histórico de 64 eventos do eletrificador deixa de ser inundado por
  "Acesso por download" (cada login gravava um).
- Novas entidades: `sensor.ultimo_evento_cerca` e `event.cerca_eletrica` (eventos
  do painel: disparo, pânico, arme, desarme, bypass, energia…).
- Uma recusa do painel (ex.: bypass com o alarme armado) não derruba a sessão.
- **Atenção:** com o add-on rodando, o app Guardian mostra "central
  desconectada" — a nuvem aceita uma sessão por eletrificador.

## 1.0.2

- Imagens prontas no GitHub Container Registry: instalação e atualização em
  segundos, sem compilar no Home Assistant.
- Leitura do histórico de eventos no cliente de linha de comando.

## 1.0.1

- Corrige a instalação no Supervisor atual (imagem base escolhida pela
  arquitetura); remove `armv7`.

## 1.0.0

- Primeira versão do add-on: painel de alarme, switch de choque, bypass das 8
  zonas, sensores de zona, disparo, sinal e conectividade via MQTT.
