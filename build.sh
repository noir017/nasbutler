#!/usr/bin/env bash
# 编译 nasbutler 为无外部依赖的 Linux 静态单文件（SQLite 是纯 Go 实现，不需要 cgo）。
# 用法: ./build.sh [输出路径]   (默认 dist/nasbutler)
# 环境变量:
#   GOARCH=arm64   交叉编译目标架构（默认 amd64）
#   VERSION=0.1.0  写入 `nasbutler version` 的版本号（默认 dev）
set -euo pipefail

cd "$(dirname "$0")"

OUT="${1:-dist/nasbutler}"
GOARCH="${GOARCH:-amd64}"

LDFLAGS="-s -w"
if [ -n "${VERSION:-}" ]; then
    LDFLAGS="$LDFLAGS -X main.version=$VERSION"
fi

mkdir -p "$(dirname "$OUT")"

echo "==> 构建 $OUT  (linux/$GOARCH${VERSION:+, 版本 $VERSION})"
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$OUT" .

echo "==> 完成: $(ls -lh "$OUT" | awk '{print $5}')"
