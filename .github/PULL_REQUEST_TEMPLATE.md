<!--
セキュリティ脆弱性の修正はこのPRではなく、まず Security Advisories から連絡してください。
Do not submit fixes for undisclosed vulnerabilities here — contact us via Security Advisories first.
-->

## What / 変更内容

<!-- 何を変えたか -->

## Why / 理由

<!-- なぜ必要か。関連Issueがあれば Closes #123 -->

## How verified / 動作確認

<!-- 実際に何を試したか。実サイトへのスキャンを伴う変更なら、どのホストで確認したかも -->

- [ ] `cd backend && gofmt -l . && go vet ./... && go test -race ./... && golangci-lint run ./...`
- [ ] `cd frontend && npm run lint && npm run build`
- [ ] `docker compose up --build` （ビルド・依存・Dockerfileを触った場合）

## Checklist

- [ ] 変更に対応するテストを追加した（`internal/safehttp` / `internal/handlers` の変更では必須）
- [ ] 外部へリクエストを送るコードは `safehttp.NewClient` / `safehttp.NewDialer` を使っている
- [ ] APIやセットアップ手順が変わる場合、README.md と README.ja.md の両方を更新した
- [ ] SSRF・レート制限まわりを触った場合、想定した迂回手段とそれを塞いだ理由を説明に書いた
