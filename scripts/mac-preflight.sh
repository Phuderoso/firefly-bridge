#!/bin/sh
# Preflight só de leitura. Não envia prompt, não resume, não mata leader.
# Sem AGENT_PREFLIGHT_EXECUTE=1 e sem --execute, apenas imprime o plano.
# Exit 2 é o resultado esperado: o envio ao vivo continua bloqueado.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m firefly_bridge mac-preflight "$@"
