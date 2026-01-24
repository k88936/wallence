#!/bin/sh

# Validate required environment variables
if [ -z "$SUBSCRIPTIONS" ] || [ -z "$DIRECT_DOMAINS" ]; then
    echo "Error: env SUBSCRIPTIONS and DIRECT_DOMAINS must be set" >&2
    exit 1
fi

/config-gen \
  --subscriptions="$SUBSCRIPTIONS" \
  --direct-domains="$DIRECT_DOMAINS" \
  --dist=/root/.config/mihomo/

exec "$@"