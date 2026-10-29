package msg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// localeDir はクライアント側の辞書ファイルが置かれているディレクトリです。
const localeDir = "../../../frontend/src/i18n/locales"

// localeFiles は存在を保証する辞書ファイルです。
// 言語を追加したらここにも追加してください。
var localeFiles = []string{"en.json", "ja.json"}

// placeholderPattern は辞書の訳文に含まれる {{name}} 形式のプレースホルダです。
var placeholderPattern = regexp.MustCompile(`\{\{(\w+)\}\}`)

// pluralSuffixes は複数形バリアントの接尾辞です。
// 英語は _one と _other を持ち、複数形を区別しない日本語は _other だけを持ちます。
var pluralSuffixes = []string{"_one", "_other"}

// loadLocale は辞書ファイルを読み込みます。
func loadLocale(t *testing.T, name string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(localeDir, name))
	if err != nil {
		t.Fatalf("辞書 %s を読み込めません: %v", name, err)
	}
	var dict map[string]string
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("辞書 %s のJSONが不正です: %v", name, err)
	}
	return dict
}

// baseKey は複数形接尾辞を取り除いたキーを返します。
// 接尾辞が付いていた場合は second の戻り値が true になります。
func baseKey(key string) (string, bool) {
	for _, suffix := range pluralSuffixes {
		if strings.HasSuffix(key, suffix) {
			return strings.TrimSuffix(key, suffix), true
		}
	}
	return key, false
}

// TestAllKeysUnique は AllKeys にキーの重複がないことを確認します。
func TestAllKeysUnique(t *testing.T) {
	seen := make(map[string]bool, len(AllKeys))
	for _, key := range AllKeys {
		if seen[key] {
			t.Errorf("AllKeys にキーが重複しています: %s", key)
		}
		seen[key] = true
	}
}

// TestAllKeysExistInLocales は Go 側が返す全キーが各辞書で解決できることを確認します。
// 複数形を持つキーは _other バリアントで解決されます。
func TestAllKeysExistInLocales(t *testing.T) {
	for _, name := range localeFiles {
		dict := loadLocale(t, name)
		for _, key := range AllKeys {
			if _, ok := dict[key]; ok {
				continue
			}
			if _, ok := dict[key+"_other"]; ok {
				continue
			}
			t.Errorf("%s にキーがありません: %s", name, key)
		}
	}
}

// TestLocalesHaveSameKeys は辞書同士のキー集合が一致することを確認します。
// UI用のキー（analyzer.* 以外）も対象に含めるため、Go側のキー一覧とは別に検証します。
func TestLocalesHaveSameKeys(t *testing.T) {
	// 複数形バリアントは基底キー単位で比較する。
	normalized := make(map[string]map[string]bool, len(localeFiles))
	for _, name := range localeFiles {
		dict := loadLocale(t, name)
		set := make(map[string]bool, len(dict))
		for key := range dict {
			base, isPlural := baseKey(key)
			if isPlural {
				// 複数形のフォールバック先なので _other は必須。
				if _, ok := dict[base+"_other"]; !ok {
					t.Errorf("%s: %s_other がありません（複数形のフォールバックに必要です）", name, base)
				}
				set[base+" (plural)"] = true
				continue
			}
			set[key] = true
		}
		normalized[name] = set
	}

	reference := localeFiles[0]
	for _, name := range localeFiles[1:] {
		for key := range normalized[reference] {
			if !normalized[name][key] {
				t.Errorf("%s にあって %s にないキー: %s", reference, name, key)
			}
		}
		for key := range normalized[name] {
			if !normalized[reference][key] {
				t.Errorf("%s にあって %s にないキー: %s", name, reference, key)
			}
		}
	}
}

// TestLocalePlaceholdersMatch は同じキーの訳文が同じプレースホルダを使っていることを確認します。
// 片方の言語だけ {{count}} を書き忘れると差し込み値が消えるため、ここで検出します。
func TestLocalePlaceholdersMatch(t *testing.T) {
	type entry struct {
		locale       string
		placeholders []string
	}
	byKey := map[string][]entry{}

	for _, name := range localeFiles {
		for key, text := range loadLocale(t, name) {
			base, _ := baseKey(key)
			names := []string{}
			for _, m := range placeholderPattern.FindAllStringSubmatch(text, -1) {
				names = append(names, m[1])
			}
			sort.Strings(names)
			byKey[base] = append(byKey[base], entry{locale: name, placeholders: names})
		}
	}

	for key, entries := range byKey {
		want := strings.Join(entries[0].placeholders, ",")
		for _, e := range entries[1:] {
			if got := strings.Join(e.placeholders, ","); got != want {
				t.Errorf("%s: プレースホルダが一致しません（%s=[%s], %s=[%s]）",
					key, entries[0].locale, want, e.locale, got)
			}
		}
	}
}
