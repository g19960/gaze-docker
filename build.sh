#!/usr/bin/env bash
set -e

APP="gaze-docker"
OUT="dist"
VERSION="${VERSION:-dev}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

usage() {
  echo "Usage: $0 [target|all]"
  echo ""
  echo "Available targets:"
  for i in "${!TARGETS[@]}"; do
    echo "  $((i+1))) ${TARGETS[$i]}"
  done
  echo "  a) all"
  echo ""
  echo "Examples:"
  echo "  $0              # interactive menu"
  echo "  $0 all          # build all targets"
  echo "  $0 linux/amd64  # build specific target"
}

build_target() {
  local target="$1"
  local os="${target%/*}"
  local arch="${target#*/}"
  local ext=""
  [[ "$os" == "windows" ]] && ext=".exe"
  local outfile="${OUT}/${APP}-${os}-${arch}${ext}"
  local ldflags="-s -w -X main.buildVersion=${VERSION} -X main.buildCommit=${COMMIT} -X main.buildTime=${BUILD_TIME}"

  echo "  → building ${os}/${arch} ..."
  GOOS="$os" GOARCH="$arch" go build -ldflags="$ldflags" -o "$outfile" .
  echo "    ✓ ${outfile} ($(du -sh "$outfile" | cut -f1))"
}

mkdir -p "$OUT"

# Non-interactive mode
if [[ -n "$1" ]]; then
  if [[ "$1" == "all" ]]; then
    echo "Building all targets..."
    for t in "${TARGETS[@]}"; do build_target "$t"; done
    echo ""
    echo "Done. Output in ./${OUT}/"
    ls -lh "${OUT}/"
    exit 0
  elif [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage; exit 0
  else
    build_target "$1"
    exit 0
  fi
fi

# Interactive menu
echo "╔══════════════════════════════╗"
echo "║   gaze-docker build tool     ║"
echo "╚══════════════════════════════╝"
echo ""
echo "Select target(s) — space-separated numbers, or 'a' for all:"
echo ""
for i in "${!TARGETS[@]}"; do
  printf "  %d) %s\n" "$((i+1))" "${TARGETS[$i]}"
done
echo "  a) all"
echo ""
read -rp "Choice: " choice

if [[ "$choice" == "a" ]]; then
  selected=("${TARGETS[@]}")
else
  selected=()
  for c in $choice; do
    if [[ "$c" =~ ^[0-9]+$ ]] && (( c >= 1 && c <= ${#TARGETS[@]} )); then
      selected+=("${TARGETS[$((c-1))]}")
    else
      echo "Invalid choice: $c (skipping)"
    fi
  done
fi

if [[ ${#selected[@]} -eq 0 ]]; then
  echo "No valid targets selected."; exit 1
fi

echo ""
echo "Building ${#selected[@]} target(s)..."
for t in "${selected[@]}"; do build_target "$t"; done

echo ""
echo "Done. Output in ./${OUT}/"
ls -lh "${OUT}/"
