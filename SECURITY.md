# Security Policy

[English](SECURITY.md) | [日本語](#日本語)

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use [GitHub Security Advisories](https://github.com/nobuo-miura/ShieldScan/security/advisories/new) to report privately.

Please include:

- Type of issue (SSRF, XSS, authentication bypass, etc.)
- Affected file paths and the commit or version
- Steps to reproduce, ideally with a proof of concept
- Impact — what an attacker could achieve

You can expect an initial response within 7 days. This is a hobby project maintained in spare time, so please be patient with fixes.

## Supported Versions

Only the latest commit on `main` receives security fixes. There are no long-term support branches.

## Security Model

ShieldScan sends HTTP requests to arbitrary user-supplied URLs from the server. That is its entire purpose, and it also makes SSRF the primary risk. Anyone deploying this publicly should understand the following.

### What is protected

- **SSRF** — every outbound TCP connection passes through a [`net.Dialer.Control`](backend/internal/safehttp/safehttp.go) hook that inspects the actual resolved IP immediately before connecting. This blocks loopback, private, link-local, CGNAT, and other special-use ranges. Because the check happens at connect time rather than at validation time, it also defeats DNS rebinding and redirect-based bypasses.
- **Redirects** — capped at 5 hops, and each hop is re-checked. Non-`http`/`https` schemes are rejected.
- **Proxies** — `HTTP_PROXY`/`HTTPS_PROXY` are deliberately ignored. Routing through a proxy would make the real connection target the proxy, defeating the IP check.
- **Rate limiting** — 30 requests per minute per client IP.

### What is not protected

- **No authentication.** Every endpoint is public. Do not expose an instance to the internet unless you accept that anyone can use your server to scan arbitrary hosts.
- **Scan history is global and in-memory.** All users see the same latest 50 scans. Do not scan URLs containing secrets in query strings.
- **`Access-Control-Allow-Origin: *`** on the API, so any web page can call your instance.
- **JWT analysis is client-submitted.** Tokens are parsed but not stored; still, do not paste production tokens into an instance you do not control.

### Configuration that weakens security

| Environment variable | Default | Risk when enabled |
|---|---|---|
| `SHIELDSCAN_ALLOW_PRIVATE` | off | **Disables SSRF protection entirely.** Local development only — never set this on a public instance. |
| `SHIELDSCAN_TRUST_PROXY` | off | Trusts `X-Forwarded-For` for client identification. Only enable behind a reverse proxy that **overwrites** the header **and** when the backend port is not reachable from outside; otherwise clients bypass rate limiting by spoofing it. |

Enabling `SHIELDSCAN_TRUST_PROXY` requires two conditions, not one. Both are satisfied in the bundled `docker-compose.yml`:

1. The proxy **overwrites** `X-Forwarded-For` rather than appending. `nginx.conf` uses `proxy_set_header X-Forwarded-For $remote_addr`; the common `$proxy_add_x_forwarded_for` appends to whatever the client sent, leaving the spoofable value first.
2. The backend port is **not published to the host**. `docker-compose.yml` uses `expose` rather than `ports` for the backend, so the only route in is through nginx. If you publish port 8080 while trusting the header, anyone can bypass the proxy and set the header freely — strictly worse than leaving the setting off.

Without `SHIELDSCAN_TRUST_PROXY`, a reverse-proxied deployment identifies every client by the proxy's own IP, so all users share a single 30 req/min bucket and one user can lock out everyone else.

## Responsible Use

ShieldScan sends real requests to the hosts you point it at. Scan only systems you own or have explicit permission to test. Unauthorized scanning may violate computer misuse laws in your jurisdiction.

---

## 日本語

### 脆弱性の報告

**セキュリティ脆弱性は公開Issueで報告しないでください。**

[GitHub Security Advisories](https://github.com/nobuo-miura/ShieldScan/security/advisories/new) から非公開で報告してください。以下を含めていただけると助かります。

- 脆弱性の種類（SSRF・XSS・認証バイパスなど）
- 該当ファイルとコミット
- 再現手順（可能ならPoC）
- 想定される影響

7日以内に一次返信します。個人が余暇で保守しているプロジェクトのため、修正までは時間をいただくことがあります。

### サポート対象

セキュリティ修正は `main` の最新コミットにのみ提供します。LTSブランチはありません。

### セキュリティモデル

ShieldScan はユーザーが指定した任意のURLへ、サーバー側からHTTPリクエストを送ります。それがこのツールの目的そのものであり、同時に SSRF が最大のリスクである理由でもあります。公開運用する場合は以下を理解した上で行ってください。

**防御しているもの**

- **SSRF** — すべての外向きTCP接続が [`net.Dialer.Control`](backend/internal/safehttp/safehttp.go) フックを通り、接続直前に実際の解決済みIPを検査します。ループバック・プライベート・リンクローカル・CGNAT などを拒否します。検証時ではなく接続時に判定するため、DNS rebinding やリダイレクト経由の迂回も防げます。
- **リダイレクト** — 最大5ホップ、各ホップで再検査。`http`/`https` 以外のスキームは拒否します。
- **プロキシ** — `HTTP_PROXY`/`HTTPS_PROXY` は意図的に無視します。プロキシ経由になると実際の接続先がプロキシになり、IP検査が意味を失うためです。
- **レート制限** — クライアントIPあたり毎分30リクエスト。

**防御していないもの**

- **認証なし。** 全エンドポイントが公開です。インターネットに公開する場合、誰でもあなたのサーバーを踏み台に任意のホストをスキャンできる点を受け入れてください。
- **スキャン履歴はグローバルかつインメモリ。** 全利用者が同じ最新50件を閲覧できます。クエリ文字列に秘密情報を含むURLはスキャンしないでください。
- **APIは `Access-Control-Allow-Origin: *`** なので、任意のWebページから呼び出せます。
- **JWT解析は利用者が貼り付けたトークンを扱います。** 保存はしませんが、自分の管理外のインスタンスに本番トークンを貼らないでください。

**セキュリティを弱める設定**

| 環境変数 | 既定 | 有効化時のリスク |
|---|---|---|
| `SHIELDSCAN_ALLOW_PRIVATE` | 無効 | **SSRF防御が完全に無効になります。** ローカル開発専用。公開インスタンスでは絶対に設定しないでください。 |
| `SHIELDSCAN_TRUST_PROXY` | 無効 | クライアント識別に `X-Forwarded-For` を信頼します。このヘッダーを**上書きする**リバースプロキシ配下で、**かつバックエンドポートが外部から到達不能**な場合にのみ有効にしてください。 |

`SHIELDSCAN_TRUST_PROXY` の有効化には条件が2つあります。同梱の `docker-compose.yml` は両方を満たしています。

1. プロキシが `X-Forwarded-For` を **追記ではなく上書き** すること。`nginx.conf` では `proxy_set_header X-Forwarded-For $remote_addr` を使っています。よく使われる `$proxy_add_x_forwarded_for` はクライアントが送った値の後ろに追記するため、偽装値が先頭に残ってしまいます。
2. バックエンドのポートを **ホストに公開しない** こと。`docker-compose.yml` はバックエンドに `ports` ではなく `expose` を使っており、経路は nginx 経由のみです。8080番を公開したままヘッダーを信頼すると、プロキシを迂回して自由にヘッダーを設定できるようになり、設定しない場合より明確に危険です。

なお `SHIELDSCAN_TRUST_PROXY` を設定しないままリバースプロキシ配下で動かすと、全クライアントがプロキシのIPとして識別されます。その結果、利用者全員で毎分30リクエストのバケットを共有することになり、1人が他の全員を429に追い込めてしまいます。

### 利用上の注意

ShieldScan は指定されたホストへ実際にリクエストを送信します。自分が所有しているか、明示的な許可を得たシステムのみをスキャンしてください。無断スキャンは各国の法令に抵触する可能性があります。
