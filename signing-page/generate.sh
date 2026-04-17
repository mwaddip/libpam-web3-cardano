#!/bin/bash
#
# Generate signing-page/index.html from template.html.
#
# Substitutes {{VARIABLE}} placeholders in template.html with values from
# environment variables (or built-in defaults). Writes the result to
# index.html alongside template.html. The bundle (engine.js) stays as a
# separate file referenced by <script src="engine.js">.
#
# Per-template-interface contract: this is the "generator" that combines
# template + variables → index.html. Run this after editing template.html.
#
# Usage:
#   ./generate.sh                    # use built-in defaults
#   PRIMARY_COLOR='#abcdef' ./generate.sh
#   RPC_URL='https://api.koios.rest/api/v1' ./generate.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$SCRIPT_DIR/template.html"
OUTPUT="$SCRIPT_DIR/index.html"

if [ ! -f "$TEMPLATE" ]; then
  echo "ERROR: template not found: $TEMPLATE" >&2
  exit 1
fi

# Defaults — chain accent + page title are baked into the shipped index.html.
# CONFIG values default to empty; downstream regenerators (e.g. blockhost
# provisioner) replace them with real chain config when needed.
: "${PAGE_TITLE:=Cardano Authentication}"
: "${PRIMARY_COLOR:=#0033AD}"
: "${ENGINE_NAME:=cardano}"
: "${PUBLIC_SECRET:=}"
: "${SERVER_PUBLIC_KEY:=}"
: "${RPC_URL:=}"
: "${NFT_CONTRACT:=}"
: "${SUBSCRIPTION_CONTRACT:=}"

# Escape sed replacement metacharacters: backslash, ampersand, and the
# delimiter we use (|).
escape_sed() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

sed \
  -e "s|{{PAGE_TITLE}}|$(escape_sed "$PAGE_TITLE")|g" \
  -e "s|{{PRIMARY_COLOR}}|$(escape_sed "$PRIMARY_COLOR")|g" \
  -e "s|{{ENGINE_NAME}}|$(escape_sed "$ENGINE_NAME")|g" \
  -e "s|{{PUBLIC_SECRET}}|$(escape_sed "$PUBLIC_SECRET")|g" \
  -e "s|{{SERVER_PUBLIC_KEY}}|$(escape_sed "$SERVER_PUBLIC_KEY")|g" \
  -e "s|{{RPC_URL}}|$(escape_sed "$RPC_URL")|g" \
  -e "s|{{NFT_CONTRACT}}|$(escape_sed "$NFT_CONTRACT")|g" \
  -e "s|{{SUBSCRIPTION_CONTRACT}}|$(escape_sed "$SUBSCRIPTION_CONTRACT")|g" \
  "$TEMPLATE" > "$OUTPUT"

echo "Generated: $OUTPUT"
