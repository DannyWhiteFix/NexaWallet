#!/bin/bash
set -e

if [[ "$1" == "nexa-cli" || "$1" == "nexa-tx" || "$1" == "nexad" || "$1" == "test_nexa" ]]; then
  mkdir -p "$NEXA_DATA"

  if [[ ! -s "$NEXA_DATA/nexa.conf" ]]; then
    cat <<EOF > "$NEXA_DATA/nexa.conf"
    printtoconsole=1
    rpcallowip=::/0
    rpcpassword=${NEXA_RPC_PASSWORD:-password}
    rpcuser=${NEXA_RPC_USER:-nexa}
EOF
    chown nexa:nexa "$NEXA_DATA/nexa.conf"
  fi

  # ensure correct ownership and linking of data directory
  # we do not update group ownership here, in case users want to mount
  # a host directory and still retain access to it
  chown -R nexa "$NEXA_DATA"
  ln -sfn "$NEXA_DATA" /home/nexa/.nexa
  chown -h nexa:nexa /home/nexa/.nexa

  exec gosu nexa "$@"
fi

exec "$@"
