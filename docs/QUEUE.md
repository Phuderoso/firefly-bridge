# Outbox persistente (`[channel_queue]`)

A fila do firefly-bridge pode gravar o estado em disco para sobreviver a um restart do daemon.

## Liga / desliga

- Sem `[channel_queue]` (ou com `state_path` vazio) a Outbox continua **só em memória**, igual ao comportamento anterior. Nada é escrito.
- Com `state_path` apontando para um arquivo JSON, cada mudança de estado (enqueue, defer, settle, in_flight) é gravada. No start, a Outbox carrega o arquivo e `next_due_at()` reflete o que foi restaurado, para o timer único rearmar.

O daemon lê o caminho com `load_queue_state_path(cfg.config_path)`. `state_path` **não** entra em `BridgeConfig`. O diretório pai precisa existir: a Outbox não cria pais.

## O que vai no arquivo

JSON único, `v = 2` (lê também `v = 1`, slima registros antigos). Campos:

- **pending** / **in_flight**: ids, `body` **sem assinatura**, sender, attempts, `next_attempt_at`, status, route. `outbound_text` e trailers (`[msgsig …]`, `channel-sig`) **não** são persistidos.
- **completed**: só `message_id`, estado terminal, `settled_at` e `body_sha256`. Sem body, sem assinatura. Cap 1024 (os mais antigos saem); não entram em `max_outbox`. Isso mantém o arquivo bem abaixo do teto de 1 MiB no uso normal (milhares de mensagens de ~1,2 KiB).

Tempos relativos a `saved_at`, com `saved_wall`. Mesma época (`now() >= saved_at`): instante absoluto. Monotônico zerado: aplica o restante a `now`, descontando o tempo de parede. Se o prazo **já venceu** no reboot, não dispara na hora: o due é no mínimo `now + backoff_base` (o primeiro degrau de `backoff`). `runner` e `presence_gate` não são persistidos.

## Assinatura (msgsig / channel-sig)

Decisão: persistir **só o texto sem assinatura** (`body`) e **reassinar no envio**. O daemon passa `sign_outbound=self.session.build_outbound(...)` (chave HMAC do próprio daemon). O hook roda no `pump_once` antes do presence gate e do runner. Se o hook faltar ou o texto sair vazio, a mensagem **não é enviada**: falha fechada (`outbound_sign_missing` / `outbound_text_empty` / `outbound_sign_failed:...`). Chaves HMAC e tokens nunca entram no arquivo; um campo denylistado no load vai para quarentena.

`privacy.safe()` não é o payload. `result`, cards e o `Event` `cancel_requested` não são gravados.

## Idempotência e o que não reenvia

A enqueue é idempotente por `message_id`. Ids terminais também ficam conhecidos depois do restart (pelo índice slim). O conflito com outro corpo é detectado pelo `body_sha256`. Um `in_flight` no checkpoint **não** é reenviado: vai para completed como `unknown` (`TIMED_OUT`) com reason `in_flight_at_restart`.

## Escrita atômica, flock e corrupção

- tmp no mesmo diretório, `fsync`, `chmod 0600`, `os.replace`, `fsync` do diretório (best-effort).
- flock exclusivo no sidecar `<arquivo>.lock` (0600). Se o `fcntl.flock` falhar, a escrita **não** segue sem lock (`QueueStoreError`); o `_emit` captura o erro, loga `outbox_state_save_failed` e o estado em memória permanece válido (a fila não emperra). Sem `fcntl` (não-Unix): warning `outbox_state_flock_unavailable` e a escrita segue sem lock, só como best-effort.
- Se o snapshot passar de 1 MiB, a Outbox poda completed antigos e tenta de novo antes de desistir; um erro de save nunca derruba o enqueue em memória.
- Arquivo ilegível / `v` desconhecido / não-regular: **não é apagado**; vira `<arquivo>.corrupt-<ts>` (`int(now())` do relógio da Outbox), fila vazia, log. Evidência no disco.
- No load e no save, tmps órfãos **deste** estado (`.{nome}.<id>.tmp`, arquivo regular, mais velhos que o arquivo atual) são apagados. Symlink e nome fora do padrão ficam.

## Relógio

Relógio da Outbox (`now=`), sem `datetime` neste módulo. O sufixo `.corrupt-<ts>` usa `int(now())` (injetável). `saved_wall` usa `time.time()` (injetável).
