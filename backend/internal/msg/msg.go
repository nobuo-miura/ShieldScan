// Package msg は多言語化対象のメッセージを、翻訳キーと差し込みパラメータの組で表現します。
//
// このパッケージは訳文を一切保持しません。APIレスポンスに載るのはキーとパラメータだけで、
// 実際の文言はクライアント側の辞書（frontend/src/i18n/locales/*.json）で解決されます。
// サーバー側に言語を持たせないことで、スキャン履歴に保存済みの結果も
// 表示する時点の言語で読めるようになります。
package msg

// Message は翻訳キーと差し込みパラメータの組です。
//
// Params のキー名は、辞書側の {{name}} プレースホルダに対応します。
// パラメータが不要な場合、Params は JSON に出力されません。
type Message struct {
	Key    string         `json:"key"`
	Params map[string]any `json:"params,omitempty"`
}

// M はパラメータを持たないメッセージを生成します。
func M(key string) Message {
	return Message{Key: key}
}

// P はパラメータ付きのメッセージを生成します。
// kv はパラメータ名と値を交互に並べます（例: P(key, "days", 30)）。
//
// 名前が文字列でない組と、要素数が奇数の場合の余った末尾は無視します。
// 呼び出し側のタイプミスで panic させるより、該当プレースホルダが
// 未置換のまま表示される方が診断結果の欠落として気づきやすいためです。
func P(key string, kv ...any) Message {
	params := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		name, ok := kv[i].(string)
		if !ok {
			continue
		}
		params[name] = kv[i+1]
	}
	if len(params) == 0 {
		return Message{Key: key}
	}
	return Message{Key: key, Params: params}
}

// IsZero はメッセージが未設定（キーが空）かどうかを返します。
// 「アドバイスなし」のような省略可能なメッセージの判定に使います。
func (m Message) IsZero() bool {
	return m.Key == ""
}
