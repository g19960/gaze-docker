#!/usr/bin/env bash
set -e

# Set these to your own registry before use
REGISTRY=""        # e.g. ghcr.io/youruser
IMAGE="gaze-docker"
PLATFORMS="linux/amd64,linux/arm64"

usage() {
  echo "Usage: $0 <version> [options]"
  echo ""
  echo "Examples:"
  echo "  $0 v1.0.0              # build + push v1.0.0"
  echo "  $0 v1.0.0 --no-push   # build only, no push"
  echo "  $0 v1.0.0 --latest    # also tag as latest"
  echo ""
  echo "Options:"
  echo "  --no-push    build only, skip push"
  echo "  --latest     also tag and push as latest"
  echo "  --platform   override platforms (default: ${PLATFORMS})"
  exit 1
}

[[ -z "$1" || "$1" == "-h" || "$1" == "--help" ]] && usage

VERSION="$1"; shift
PUSH=true
TAG_LATEST=false
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-push)  PUSH=false; shift;;
    --latest)   TAG_LATEST=true; shift;;
    --platform) PLATFORMS="$2"; shift 2;;
    *) echo "Unknown option: $1"; usage;;
  esac
done

FULL_IMAGE="${REGISTRY}/${IMAGE}"

echo "╔══════════════════════════════════════╗"
echo "║   Docker Image Build & Push          ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  Image:     ${FULL_IMAGE}"
echo "  Version:   ${VERSION}"
echo "  Platforms: ${PLATFORMS}"
echo "  Push:      ${PUSH}"
echo "  Latest:    ${TAG_LATEST}"
echo ""

# check buildx
if ! docker buildx version &>/dev/null; then
  echo "[WARN] docker buildx not available, falling back to single-platform build"

  echo "→ building ${FULL_IMAGE}:${VERSION} ..."
  docker build \
    --build-arg VERSION="${VERSION}" \
    --build-arg COMMIT="${COMMIT}" \
    --build-arg BUILD_TIME="${BUILD_TIME}" \
    -t "${FULL_IMAGE}:${VERSION}" .

  if $TAG_LATEST; then
    docker tag "${FULL_IMAGE}:${VERSION}" "${FULL_IMAGE}:latest"
  fi

  if $PUSH; then
    echo "→ pushing ${FULL_IMAGE}:${VERSION} ..."
    docker push "${FULL_IMAGE}:${VERSION}"
    if $TAG_LATEST; then
      echo "→ pushing ${FULL_IMAGE}:latest ..."
      docker push "${FULL_IMAGE}:latest"
    fi
  fi
else
  # ensure builder exists
  BUILDER_NAME="gaze-builder"
  if ! docker buildx inspect "$BUILDER_NAME" &>/dev/null; then
    echo "→ creating buildx builder: ${BUILDER_NAME}"
    docker buildx create --name "$BUILDER_NAME" --use
  else
    docker buildx use "$BUILDER_NAME"
  fi

  TAGS="-t ${FULL_IMAGE}:${VERSION}"
  if $TAG_LATEST; then
    TAGS="${TAGS} -t ${FULL_IMAGE}:latest"
  fi

  PUSH_FLAG=""
  if $PUSH; then
    PUSH_FLAG="--push"
  else
    PUSH_FLAG="--load"
    # --load only supports single platform
    PLATFORMS="${PLATFORMS%%,*}"
    echo "[NOTE] --no-push mode: building single platform ${PLATFORMS} only"
  fi

  echo "→ building multi-platform image ..."
  docker buildx build \
    --platform "${PLATFORMS}" \
    --build-arg VERSION="${VERSION}" \
    --build-arg COMMIT="${COMMIT}" \
    --build-arg BUILD_TIME="${BUILD_TIME}" \
    ${TAGS} \
    ${PUSH_FLAG} \
    .
fi

echo ""
echo "✓ Done: ${FULL_IMAGE}:${VERSION}"
