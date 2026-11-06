#!/usr/bin/env bash
# Generátor statického SBOM webu: bash + jq (žádný Python/Node).
# Spouštěj z kořene repa:  bash scripts/build.sh
# Volitelně: OUT=_site bash scripts/build.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-_site}"
W="${TMPDIR:-/tmp}/sbom-ui-static-$$"
SCRIPT_DIR="$ROOT/scripts"
PARSE_JQ="$SCRIPT_DIR/parse.jq"
RENDER_JQ="$SCRIPT_DIR/render.jq"

cleanup() { rm -rf "$W"; }
trap cleanup EXIT

mkdir -p "$W"
rm -rf "$OUT"
mkdir -p "$OUT"

# ---- jq >= 1.7 (potřebujeme "\u0000" v -j výstupu) ----
jq_ver="$(jq --version 2>/dev/null | sed -n 's/^jq-//p')"
if [ -z "$jq_ver" ]; then
  echo "::error::jq není nainstalované" >&2
  exit 1
fi
jq_major="${jq_ver%%.*}"
jq_minor="$(echo "$jq_ver" | cut -d. -f2)"
if [ "$jq_major" -lt 1 ] || { [ "$jq_major" -eq 1 ] && [ "${jq_minor:-0}" -lt 7 ]; }; then
  echo "::error::Potřebuji jq 1.7+, mám $jq_ver" >&2
  exit 1
fi
echo "jq $jq_ver"

# ---- volitelné ruční doplnění původu ----
echo '{}' > "$W/sources.json"
if [ -f resources/sbom-sources.json ]; then
  if jq -e 'type == "object"' resources/sbom-sources.json > /dev/null 2>&1; then
    cp resources/sbom-sources.json "$W/sources.json"
  else
    echo "::warning file=resources/sbom-sources.json::resources/sbom-sources.json je neplatný JSON – ignoruji"
  fi
fi

# ---- najdi SBOMy, ověř JSON a zkopíruj je do výstupu (stejná relativní cesta) ----
files=()
for d in resources/spdx resources/cyclonedx; do
  [ -d "$d" ] || continue
  while IFS= read -r -d '' f; do
    if jq -e -s 'length == 1 and (.[0] | type) == "object"' "$f" > /dev/null 2>&1; then
      files+=("$f")
      mkdir -p "$OUT/$(dirname "$f")"
      cp "$f" "$OUT/$f"
    else
      echo "::warning file=$f::Přeskakuji $f: neplatný JSON"
    fi
  done < <(find "$d" -type f -iname '*.json' -print0 | LC_ALL=C sort -z)
done

if [ "${#files[@]}" -eq 0 ]; then
  # parse.jq s inputs bez souborů spadne – předáme prázdný validní stub přes process substitution? 
  # Lepší: vytvoř prázdný model přímo.
  now="$(TZ=Europe/Prague date '+%Y-%m-%d %H:%M %Z')"
  jq -n --arg now "$now" '{generatedAt:$now, sboms:[], components:[], log:["! Žádné platné SBOM soubory v resources/spdx/ ani resources/cyclonedx/"]}' \
    > "$W/model.json"
else
  jq -n --slurpfile ov "$W/sources.json" \
        --arg now "$(TZ=Europe/Prague date '+%Y-%m-%d %H:%M %Z')" \
        -f "$PARSE_JQ" "${files[@]}" < /dev/null > "$W/model.json"
fi

# log: řádky s "!" jako varování v Actions
jq -r '.log[]' "$W/model.json" | sed 's/^! /::warning::/'
jq -r '"Načteno: \(.sboms | length) SBOMů, \(.components | length) komponent"' "$W/model.json"

# ---- model -> HTML + CSV (jeden jq proces, NUL oddělovače) ----
OUT_ABS="$(realpath -m "$OUT")"
n=0
# shellcheck disable=SC2094
while IFS= read -r -d '' p && IFS= read -r -d '' content; do
  # pojistka proti path traversalu
  case "$p" in
    "" | /* | *\\* ) echo "::error::Neplatná cesta stránky: ${p:-<prázdná>}"; exit 1 ;;
  esac
  # segmenty s .. (i uprostřed)
  if printf '%s' "$p" | grep -Eq '(^|/)\.\.(/|$)'; then
    echo "::error::Neplatná cesta stránky (obsahuje ..): $p"
    exit 1
  fi
  target="$(realpath -m "$OUT/$p")"
  case "$target" in
    "$OUT_ABS"|"$OUT_ABS"/*) ;;
    *) echo "::error::Cesta mimo výstupní složku: $p -> $target"; exit 1 ;;
  esac
  mkdir -p "$(dirname "$target")"
  printf '%s' "$content" > "$target"
  n=$((n + 1))
done < <(jq -j -f "$RENDER_JQ" "$W/model.json")

cp docs/style2.css "$OUT/style2.css"
echo "Vygenerováno $n souborů do $OUT/"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### SBOM knihovny"
    jq -r '"- SBOMů: \(.sboms | length)\n- komponent: \(.components | length)"' "$W/model.json"
    echo "- vygenerováno souborů: $n"
  } >> "$GITHUB_STEP_SUMMARY"
fi
