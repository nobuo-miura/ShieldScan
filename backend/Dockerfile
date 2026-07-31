FROM golang:1.26-alpine AS builder
WORKDIR /app
# 現時点で外部依存はゼロなので go.sum は存在しない。
# 初めて依存を追加したら、この行に go.sum も足すこと。
COPY go.mod ./
RUN go mod download
COPY . .
# -trimpath でビルドパスを埋め込まない、-s -w でシンボルを削りバイナリを小さくする
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o server ./cmd/server

FROM alpine:3.24
# TLS診断で証明書チェーンを検証するためCA証明書が必須。
# wget は docker-compose のヘルスチェックが使う。
RUN apk --no-cache add ca-certificates wget

# セキュリティ診断ツール自身をrootで動かさない
RUN adduser -D -u 10001 shieldscan
USER shieldscan

WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
CMD ["./server"]
