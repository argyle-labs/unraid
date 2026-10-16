#!/usr/bin/env bash
set -euo pipefail

: "${UNRAID_URL:?set UNRAID_URL (e.g. https://tower.local)}"
: "${UNRAID_API_KEY:?set UNRAID_API_KEY}"
timeout="${UNRAID_TIMEOUT:-60}"
here="$(cd "$(dirname "$0")" && pwd)"
schemas="$here/../schemas"
insecure=()
[ "${UNRAID_INSECURE:-0}" = 1 ] && insecure=(-k)

gql() {
  curl -fsS "${insecure[@]}" --connect-timeout 10 --max-time "$timeout" \
    -H 'Content-Type: application/json' -H "x-api-key: $UNRAID_API_KEY" \
    -d "$1" "${UNRAID_URL%/}/graphql"
}

version="$(gql '{"query":"{ vars { version } }"}' | jq -er '.data.vars.version')"
version="${version%%[!0-9.]*}"
committed="$schemas/$version.introspection.json"
live="$(mktemp)"
trap 'rm -f "$live"' EXIT
gql "$(jq -n --rawfile q "$here/introspection.graphql" '{query: $q, operationName: "IntrospectionQuery"}')" > "$live"

if [ ! -f "$committed" ]; then
  echo "no committed schema for Unraid $version; pull it with the unraid.schema tool (from, api_key, dir=schemas)" >&2
  exit 2
fi

if diff -u <(jq -S '.data.__schema' "$committed") <(jq -S '.data.__schema' "$live"); then
  echo "Unraid $version schema matches $committed"
else
  echo "Unraid $version schema drifted from $committed" >&2
  exit 1
fi
