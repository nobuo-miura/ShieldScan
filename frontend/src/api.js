// APIの呼び出しとエラー応答の受け取りをまとめます。
//
// エラー本文は訳文ではなく {key, params} 形式の翻訳キーで返るため、
// 表示側で辞書を引けるよう、例外にそのまま載せて運びます。

// ApiError は API が 2xx 以外を返したことを表します。
// detail には翻訳キー形式のメッセージが入ります。
export class ApiError extends Error {
  constructor(detail) {
    const message = typeof detail === 'string' ? detail : detail?.key
    super(message ?? 'api.error.unknown')
    this.name = 'ApiError'
    this.detail = detail ?? { key: 'api.error.unknown' }
  }
}

// postJSON は JSON を POST し、エラー応答を [ApiError] として投げます。
export async function postJSON(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) throw new ApiError(data.error)
  return data
}

// errorMessage は catch した例外から表示用のメッセージを取り出します。
// fetch 自体が失敗した場合（ネットワークエラーなど）は素の文字列が返り、
// 翻訳関数 tm はそれをそのまま表示します。
export function errorMessage(e) {
  return e instanceof ApiError ? e.detail : e.message
}
