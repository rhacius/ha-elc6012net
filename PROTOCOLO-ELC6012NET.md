# Protocolo de comunicação — Intelbras ELC 6012 NET (via app Guardian)

**Fonte:** engenharia reversa do `base.apk` (`br.com.intelbras.amtremotomobile`) com REA —
decompilação do `Amt2k.Core.DotnetStandard.dll` e decodificação do CIL — **mais validação
ao vivo** contra um ELC 6012 NET real (modelo `0x35`; MAC dos exemplos é fictício).

---

## 1. Arquitetura (descoberta importante)

O ELC 6012 NET tem **dois caminhos de comunicação**:

| Caminho | Função |
|---|---|
| **TCP 9009 local** (LAN) | **Somente descoberta**: 2 sondas (MAC e modelo). Nenhum comando de controle é aceito — pacotes de sessão são ignorados em silêncio. É a única porta TCP aberta. |
| **Nuvem Intelbras** (relay) | **Todo o controle**: status, arme/desarme, bypass, eventos. TCP puro, sem TLS. O painel mantém conexão permanente com o relay; o app (ou este cliente) conecta no relay e é roteado até o painel pelo MAC. |

Servidores (porta 9009 em ambos):

1. `amt.intelbras.com.br` — servidor "geral": informa em qual relay o painel está.
2. `amt8000.intelbras.com.br` — relay da linha AMT 8000 / ELC (onde a sessão acontece).

Sequência completa de sessão (validada ao vivo):

```
[a] TCP -> amt.intelbras.com.br:9009
    -> CloudPacket(0xE5, buf20)         buf20 = [04, MAC, 00, 01, MAC, 00x5]
    <- 1 byte: FD  (= "painel está no servidor AMT8000"; FE = painel offline)

[b] TCP -> amt8000.intelbras.com.br:9009   (uma conexão para toda a sessão)
    -> Packet(0x30F6, appid16)          appid16 = [01, 00 x14, 01]   <- ACK F0FE
    -> Packet(0xFFF0, mac_ascii12)      ex.: "001A3F123456"          -> F0FE
    -> Packet(0xF0F0, login9)           [01, senha6, 10, 00]         -> F0F0, [8]=0 (OK)
    -> comandos... (status / arme / desarme / bypass / eventos)
```

### 1.1 Uma sessão por painel (validado ao vivo, 27/out/2026)

O relay aceita **uma sessão por painel**. Enquanto uma sessão estiver aberta, um
novo login recebe **NACK código 50** e o app Guardian mostra "central
desconectada". Uma sessão aberta aguenta consultas periódicas indefinidamente
(testado: 12 min, inclusive 120 s parada) com ~0,3 s por consulta. Ao fechar uma
sessão, o relay pode levar alguns segundos para liberar o painel.

---

## 2. Enquadramento

### 2.1 Packet "AMT8000" (binds, login, arme) — `Packet::.ctor(cmd, data, isRemote)`
```
byte 0..3 : 00 00 00 F1   (isRemote=false — binds e comandos; o app usa
                           00 00 00 00 quando IsRemoteConnection=true;
                           o relay aceita ambos — verificado)
byte 4..5 : len BE        len = len(payload) + 2
byte 6..7 : comando BE
byte 8..  : payload
último    : checksum
```

### 2.2 PacketFence (status 0x0B4A)
Idêntico, mas marker = `00 00 8F FF`.

### 2.3 CloudPacket (servidor geral 0xE5)
```
byte 0    : 1 + len(data)
byte 1    : comando (1 byte)
byte 2..  : data
último    : checksum
```

### 2.4 Checksum (todos os formatos)
```python
chk = XOR de todos os bytes anteriores; chk ^= 0xFF
```

### 2.5 Respostas do relay
```
byte 0..3 : prefixo do relay (00 00 00 00 / 00 01 00 00 — varia; ignorar)
byte 4..5 : len BE   (ACK/login: total = len + 7; NACK: len + 8, ver abaixo;
                     status 0x0B4A: total = len + 1, ex.: len=0xA4 em frames de
                     165 bytes; eventos 0x3900: sempre 129 bytes, §6.1)
byte 6..7 : eco do comando (ou F0FE=ACK de bind, F0FD=NACK/erro)
byte 8..  : payload (no NACK: [8] = código de erro)
último    : checksum
```

**Atenção — NACK do relay:** o `len` não conta o byte do código de erro. Ex.
(login recusado, código 50 = 0x32, com sessões em sequência rápida):
`00 02 00 00 00 02 F0 FD 32 C0` — `len=2`, mas o frame tem 10 bytes; `C0` é o
checksum. Quem lê pelo `len` precisa consumir 1 byte a mais no NACK.

### 2.6 Formato "2018" (painéis antigos — NÃO usado pelo ELC na nuvem)
`[len_total][cmd][len_dados][dados][CRC16 LE][chk]`, CRC-16/CCITT-FALSE-revertido
(tabela em `crc_table_2018.txt`). O ELC responde NACK a estes pacotes via relay.
(O app usa este formato em conexões locais com centrais AMT antigas e no
handshake `E7 [10]` / identify `E7 [11 pw 34]` do caminho 2018.)

### 2.7 Sondas de descoberta local (porta 9009 do ELC)
Mini-framing `[len][cmd][dados][chk]`:

- Pedir MAC:    `01 C4 3A` -> `07 C4 <MAC 6B> <chk>`   (ex.: 07 C4 00 1A 3F 12 34 56 69)
- Pedir modelo: `01 C2 3C` -> `02 C2 <modelo> <chk>`   (ex.: 02 C2 35 0A -> 0x35)

Uma sonda por conexão TCP (o ELC fecha após responder).

---

## 3. Login (comando 0xF0F0)

Payload (9 bytes): `01 <senha6> 10 00`

- `senha6`: **cada caractere da senha vira 1 byte** (`Convert.ToByte(c,16)`);
  completa com `00` até 6. Ex.: `1234` -> `01 02 03 04 00 00`.
- Resposta: eco `F0F0`, `[8]` = código (0 = OK; 25 = senha inválida; o app
  também aceita 12). Validação do app (`TranslateAmt8000`): se `resp[1]==0xE7`,
  o código é lido em `[10]` (resposta envelopada).

Obs.: a senha do ELC é a mesma cadastrada no app Guardian para o dispositivo.

## 4. Status (comando 0x0B4A, PacketFence)

Resposta de 165 bytes (offsets incluem os 4 bytes de prefixo do relay):

| Offset | Significado |
|---|---|
| `[6..7]` | eco `0B 4A` |
| `[8]` | modelo (`0x35` = ELC 6012 NET) |
| `[30]` bit0 | **CHOQUE** — alta tensão ativa na cerca (independe do alarme) |
| `[31]` bit0 | **ALARME armado** (no app, "armado" = `[30].0 AND [31].0`) |
| `[31]` bit1 | STAY |
| `[46..47]` | bitmask LE de zonas abertas (bit0 = zona 1). O app lê só `[46]`: **o ELC tem 8 zonas** (idem `[54]` e `[62]`) |
| `[54..55]` | bitmask LE de zonas disparadas — da decompilação, ainda não visto com disparo real |
| `[62..63]` | bitmask LE de zonas em bypass (validado: zona 1 anulada → `[62]=0x01`) |
| `[72..77]` | dia, mês, ano, hora, min, seg (relógio do painel) |
| `[79]` bit0 | alimentação: 1 = bateria (`ACTIVE_BATTERY`), 0 = rede AC (`AC_POWER_OK`) — da decompilação, não validado |
| `[145]` bits 0/1 | PGM 1 / PGM 2 ligada — da decompilação, não validado |
| `[157..162]` | MAC do ELC (validado) |
| `[163]` | sinal: `<=37 -> 100%`; senão `174 - 2*v` % |
| `[164]` | checksum |

## 5. Arme / desarme (comando 0x401E)

Payload (2 bytes): `[partição, modo]`

- **partição** — o ELC tem alarme e choque independentes. `OnlineInterpreter.ReadFenceStatus`
  cria três partições (nomes do enum `ItemKeys`):

  | Partição | Nome no app | Estado no status |
  |---|---|---|
  | **255** | `ACTIVATE_ALARM_SHOCK` (alarme + choque) | `[30].0 AND [31].0` |
  | **1** | `ACTIVATE_ALARM_ONLY` (só alarme) | `[31].0` |
  | **2** | `ACTIVATE_SHOCK_ONLY` (só choque — botão de choque do app) | `[30].0` |

  As três validadas ao vivo (27/out/2026). O NACK `0x21` de um teste antigo com
  partição 0/1 era outra causa (provavelmente sem login); a partição 0 não existe no ELC.
- modo (`OnlineFenceDataSource.ActivatePanel`): **1 = ativar**, **0 = desativar**,
  2 = stay (só se `stay && isActivating`; não se aplica ao ELC)

**Resposta: o próprio status completo (165 bytes, eco 0x0B4A)** — o painel já
devolve o novo estado, não um ACK simples.

Erros conhecidos (`Get8000Error`): 0=OK, 25=senha inválida, 27/32=partição sem
zonas habilitadas, 39=zonas abertas, 42=operação negada, 46/54/63/68/70=outros.
Observados ao vivo: `0x21` (33) num teste antigo (partição 0 ou sem login) e 50
(`0x32`) no login com outra sessão ativa (§1.1); uma vez, código 0 num NACK de
login logo após outra sessão (significado incerto).

## 6. Outros comandos (enum `CommandTypesAmt8000`)

| Comando | Código | Observação |
|---|---|---|
| Status básico | `0x0B01` | (sem resposta do ELC via relay no teste) |
| Parar sirene | `0x4019` | (sem resposta do ELC — não implementado) |
| Limpar disparo | `0x4013` | (idem) |
| PGM | `0x45AF` | `ElcWriteInformationBuilder.WriteTogglePgm`: `[pgm-1, bool]`. Estado no status: PGM 1 (`PGM_DISP`) = `[145].0`, PGM 2 (`PGM_ARM`) = `[145].1` |
| Bypass de zona | `0x401F` | payload `[255, z1, z2, …]`: **1 byte por zona** (1 = anulada, 0 = normal), na ordem da lista de zonas (WriteZoneCancelling) — só com o sistema **desarmado**. Define **todas** as zonas de uma vez (não é toggle). Resposta: status (eco `0x0B4A`) |

**Bypass exige o sistema desarmado:** o painel só aceita anular (ou reativar) uma
zona com a cerca desarmada. Para armar com uma zona com defeito: desarmar →
anular a zona → armar. O estado de bypass aparece no status em `[62..63]`.

### 6.1 Buffer de eventos (comando 0x3900) — validado ao vivo (27/out/2026)

`GeneralEventsElc6012NetDataSource.ReadData` lê **8 páginas**: `Packet(0x3900, [página])`
(marker `00 00 00 00`), página 0–7; resposta com eco `0x3900`, interpretada por
`ElcInterpreterInformation.ReadEventsData`. A resposta tem **sempre 129 bytes**
(8 + 8 × 15 + 1), embora o `len` venha `0x82` (130) — não segue nem a regra do
status nem a dos ACKs; leia pelo tamanho fixo.

Cada página traz até 8 registros de **15 bytes**, a partir de `[8]` (o app lê
enquanto o início do registro for < 128). Registro começando com `FF` = vazio.

| Offset no registro | Conteúdo |
|---|---|
| `[0..3]` | código **Contact ID**, um dígito por byte, com 0 escrito como `A` (ex.: `01 01 03 0A` = 1130: qualificador 1 + evento 130) |
| `[5]` | partição: 1 = alarme, 2 = choque, 15 = alarme e choque (o app trata `1131` na partição 1 como choque) |
| `[7..8]` | zona/usuário (dois bytes exibidos lado a lado) |
| `[9..11]` | dia, mês, ano |
| `[12..14]` | hora, minuto, segundo |

Nomes (`Elc6012Net.EVENTS_TRANSLATED`): procura primeiro a chave de 4 dígitos
(com o qualificador — ex.: `14A1` desarme por usuário, `34A1` arme por usuário) e
depois a de 3 (ex.: `13A` disparo de zona, `57A` bypass, `3A1` falta de AC,
`461` senha incorreta, `422` PGM). Lista completa em `EVENT_NAMES` no cliente.
**Disparo do choque** (manual: o setor de choque dispara por rompimento/aterramento
da cerca após N pulsos falhos, padrão 10, mesmo com o alarme desarmado): Contact ID
**131** (perímetro) — `1131` disparo, `3131` restauração. Fora do `EVENTS_TRANSLATED`;
o app só o reconhece pela regra "1131 na partição 1 = choque". Inferido da
decompilação + manual; ainda não visto ao vivo. Qualificador 3 = restauração
(também `3301` = energia AC de volta).

**Página 0 = eventos mais recentes**; dentro de cada página, do mais novo para o
mais antigo. Buffer de **64 eventos**.

**Cada login na nuvem grava "Acesso por download" (E410)**. Com uma sessão por
poll de 60 s, o buffer cobria só ~1 h e os eventos reais saíam dele (também do
histórico do app Guardian) — por isso a ponte mantém uma sessão só (§1.1).
Validado: arme/desarme remoto aparecem como `34A7`/`14A7` com a partição certa
(1 = alarme, 2 = choque).

## 7. Senha em pares (formato 2018 — identify/handshake)

`Converters.GetPartsInBytes(s, n)`: pega pares de caracteres e converte como hex
(`"1234"` -> `[0x12, 0x34]`). Usado no `SendIdentify` do caminho 2018 —
**não necessário para o ELC via nuvem** (o login 0xF0F0 usa dígitos isolados).

---

## 8. Validação prática (ELC real, 26–27/out/2026)

| Etapa | Resultado |
|---|---|
| Sonda MAC local | ✅ `07 C4 00 1A 3F 12 34 56 69` |
| Sonda modelo local | ✅ `02 C2 35 0A` |
| Sessão/pacotes locais na 9009 | ❌ silêncio (porta é só descoberta) |
| CloudPacket 0xE5 (amt.intelbras) | ✅ resposta `FD` |
| Bind appID / MAC (amt8000) | ✅ `F0FE` |
| Login 0xF0F0 (senha do app) | ✅ `F0F0`, erro 0 |
| Status 0x0B4A | ✅ 165 bytes, checksum OK |
| Desarme `0x401E [255,0]` | ✅ status com `[30]=0x80` (choque OFF) |
| Arme `0x401E [255,1]` | ✅ status com `[30]=0x81` (choque ON) |
| Alarme desarmado com choque ativo (pelo app, 27/out/2026) | ✅ `[30]=0x81 [31]=0x80` — choque e alarme são independentes; `[14]` foi `01` nessa leitura, mas `00` em outras com o mesmo estado — não indica o alarme |
| Só choque `0x401E [2,0]` / `[2,1]` (27/out/2026) | ✅ `[30]` `0x81`→`0x80`→`0x81`; `[31]=0x80` inalterado (alarme continua desarmado) |
| Só alarme `0x401E [1,1]` / `[1,0]` (27/out/2026, choque desligado) | ✅ `[31]` `0x80`→`0x81`→`0x80`; `[30]=0x80` inalterado — **alarme arma sem choque** |
| Comando logo após vários seguidos | ⚠️ login OK, painel não respondeu ao `0x401E` (resposta vazia), **mas aplicou o comando** (choque ligou, conferido no app). O cliente agora consulta o status na mesma sessão para confirmar |
| Bypass `0x401F [255,0,1,0,0,0,0,0,0]` e volta (27/out/2026) | ✅ `[62]` `0x00`→`0x02`→`0x00` (zona 2); resposta = status |
| Bypass zona 1 (pelo app, 27/out/2026) | ✅ status com `[62]=0x01`; armado com zona anulada (`[30]=0x81 [31]=0x81`) |
| Login com outra sessão ativa no painel | ⚠️ NACK código 50 (`0x32`) — o relay aceita **uma sessão por painel** (ver §1.1) |
| Sessão única por 12 min (16 consultas, intervalos de 30/60/120 s) | ✅ sem queda, ~0,3 s por consulta; durante ela o app Guardian mostra "central desconectada" |
| Eventos `0x3900` páginas 0–7 | ✅ 129 bytes cada; página 0 = mais recentes; arme/desarme remoto como `34A7`/`14A7` |
| Bypass/reativação de zona pelo `0x401F` com o alarme desarmado | ⚠️ **não gera evento** no buffer (zona 8, 27/out/2026) |
| Disparo de zona / do choque (`[54]`, evento 131), alimentação `[79]`, PGM `[145]` | ⏳ não validados ao vivo (disparo exige romper/aterrar a cerca) |

## 9. Referências de código (IL decodificado)

- `Packet::.ctor` (rows 855/856/857) — formatos 2018 / marker 0000 / F1 vs 0000 (isRemote)
- `PacketFence::.ctor` — marker 8F FF
- `CloudPacket` — formato do servidor geral
- `LoginRepository.CloudLogin / ConnectCloudAmt8000 / OpenAmt8000 / GetMacPacket / SendIdentify`
- `OnlineFenceDataSource.<ActivatePanel>d__4` — arme do fence (0x401E)
- `OnlineInterpreter.ReadFenceStatus` — layout do status
- `Converters.Translate / TranslateAmt8000` — validação de respostas
- `InterpreterInformationAmt8000.Get8000Error` — tabela de erros
- `Checksum::Calculate` — XOR + complemento
- `Crc::ComputeChecksum` — CRC-16 (formato 2018)
