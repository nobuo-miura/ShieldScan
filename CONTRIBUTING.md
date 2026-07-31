# Contributing to ShieldScan

[English](CONTRIBUTING.md) | [日本語](#日本語)

Thanks for your interest. This is a small project, so the process is light.

## Before you start

- **Found a security vulnerability?** Do not open an issue — see [SECURITY.md](SECURITY.md).
- **Planning a large change?** Open an issue first so we can agree on the approach before you write code.
- **Small fix?** Just send a pull request.

## Development setup

Requires Go 1.26+, Node 24+, and optionally Docker.

```bash
git clone https://github.com/nobuo-miura/ShieldScan
cd ShieldScan
```

Run the backend (port 8080):

```bash
cd backend && go run ./cmd/server
```

Run the frontend in a separate terminal (port 5173, proxies `/api` to the backend):

```bash
cd frontend && npm install && npm run dev
```

### Scanning localhost during development

SSRF protection blocks private addresses by default, so you cannot scan a service on your own machine. Opt out for local work only:

```bash
(cd backend && SHIELDSCAN_ALLOW_PRIVATE=true go run ./cmd/server)
```

Never set this on a public instance — see [SECURITY.md](SECURITY.md).

## Before opening a pull request

Everything below runs in CI, so running it locally saves a round trip.

Run these from the repository root. Each uses a subshell, so they can be pasted one after another:

```bash
(cd backend && gofmt -l . && go vet ./... && go test -race ./... && golangci-lint run ./...)
(cd frontend && npm run lint && npm run build)
```

Full stack, as a clean clone would see it:

```bash
docker compose up --build
```

## Conventions

- **Commit messages in English**, following [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `refactor:`, `test:`.
- **Code comments in Japanese are fine** — that is the existing style. Explain *why*, not *what*.
- **Go**: follow `gofmt` and the `golangci-lint` config in [backend/.golangci.yml](backend/.golangci.yml). Exported identifiers get doc comments.
- **React**: functional components only, hooks over classes.
- **Tests**: any change to `internal/safehttp` or `internal/handlers` needs tests. Those packages are where the security-relevant logic lives.

## What makes a good pull request

- One logical change per PR.
- Explain the *why* in the description, not just the *what*.
- If you change scan behavior, say how you verified it against a real host.
- If you touch SSRF handling, describe the bypass you considered and why it is closed.

## Adding a new scan type

Each scan lives in its own file under `backend/internal/analyzer/` with a matching handler in `backend/internal/handlers/handlers.go` and a tab component in `frontend/src/components/`. When you add one:

1. Take a `context.Context` as the first parameter and thread it into every request.
2. Use `safehttp.NewClient` or `safehttp.NewDialer` — never construct a bare `http.Client`. That is what keeps SSRF protection in place.
3. Validate the target with `safehttp.ValidateURL` in the handler before scanning.

---

## 日本語

小さなプロジェクトなので、プロセスは軽めです。

### 始める前に

- **脆弱性を見つけた場合** はIssueを立てず、[SECURITY.md](SECURITY.md) を参照してください。
- **大きな変更を予定している場合** は、実装前にIssueで方針をすり合わせましょう。
- **小さな修正** はそのままPRを送ってください。

### 開発環境

Go 1.26以降、Node 24以降が必要です（Dockerは任意）。

バックエンド（ポート8080）:

```bash
cd backend && go run ./cmd/server
```

フロントエンド（別ターミナル、ポート5173。`/api` をバックエンドにプロキシします）:

```bash
cd frontend && npm install && npm run dev
```

**開発中に localhost をスキャンしたい場合**、既定ではSSRF防御がプライベートアドレスを拒否します。ローカル作業に限り以下で無効化できます。

```bash
(cd backend && SHIELDSCAN_ALLOW_PRIVATE=true go run ./cmd/server)
```

公開インスタンスでは絶対に設定しないでください。

### PRを出す前に

以下はすべてCIでも実行されます。手元で通しておくと往復が減ります。

```bash
(cd backend && gofmt -l . && go vet ./... && go test -race ./... && golangci-lint run ./...)
(cd frontend && npm run lint && npm run build)
docker compose up --build
```

### 規約

- **コミットメッセージは英語**、[Conventional Commits](https://www.conventionalcommits.org/) 形式（`feat:` `fix:` `docs:` `chore:` `ci:` `refactor:` `test:`）。
- **コードコメントは日本語でOK**（既存のスタイルです）。*何を* ではなく *なぜ* を書いてください。
- **Go**: `gofmt` と [backend/.golangci.yml](backend/.golangci.yml) の設定に従う。エクスポートされた識別子にはdocコメントを付ける。
- **React**: 関数コンポーネントのみ、クラスではなくフックを使う。
- **テスト**: `internal/safehttp` と `internal/handlers` への変更にはテストが必要です。セキュリティ上重要なロジックがある場所です。

### 新しいスキャン種別を追加する場合

各スキャンは `backend/internal/analyzer/` の個別ファイル、`backend/internal/handlers/handlers.go` のハンドラー、`frontend/src/components/` のタブコンポーネントで構成されます。追加時は:

1. 第1引数に `context.Context` を取り、全リクエストに引き渡すこと。
2. `safehttp.NewClient` / `safehttp.NewDialer` を使うこと。素の `http.Client` を作らないでください。SSRF防御が外れます。
3. ハンドラーでスキャン前に `safehttp.ValidateURL` を通すこと。
