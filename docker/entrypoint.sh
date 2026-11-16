#!/bin/sh
set -eu

/config-gen \
  --subscriptions="$SUBSCRIPTIONS" \
  --direct-domains="$DIRECT_DOMAINS" \
  --dist=/root/.config/mihomo/

exec "$@"
