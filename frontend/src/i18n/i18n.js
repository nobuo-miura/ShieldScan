// 辞書の読み込みと翻訳関数を提供します。
//
// バックエンドは訳文ではなく翻訳キーと差し込みパラメータ（{key, params}）を返すため、
// 診断結果の文言もここで組み立てます。保存済みのスキャン履歴も表示時に訳されるので、
// 言語を切り替えると過去の結果まで切り替わります。
import { createContext, useContext } from 'react'

import en from './locales/en.json'
import ja from './locales/ja.json'

const LOCALES = { en, ja }

// FALLBACK_LANG は辞書にキーが無い場合の参照先です。
export const FALLBACK_LANG = 'en'

// STORAGE_KEY はユーザーが選んだ言語の保存先キーです。
const STORAGE_KEY = 'shieldscan.lang'

// SUPPORTED_LANGS は言語切り替えUIに並べる言語の一覧です。
export const SUPPORTED_LANGS = [
  { code: 'en', label: 'English', short: 'EN' },
  { code: 'ja', label: '日本語', short: 'JA' },
]

const PLACEHOLDER = /\{\{(\w+)\}\}/g

// pluralRulesCache は Intl.PluralRules の生成コストを避けるためのキャッシュです。
const pluralRulesCache = new Map()

function pluralRules(lang) {
  let rules = pluralRulesCache.get(lang)
  if (!rules) {
    rules = new Intl.PluralRules(lang)
    pluralRulesCache.set(lang, rules)
  }
  return rules
}

// detectLang は表示言語を決定します。
// 保存済みの選択 → ブラウザの言語設定 → 英語 の順に判定します。
export function detectLang() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved && LOCALES[saved]) return saved
  } catch {
    // プライベートモードなどで localStorage が使えない場合は無視して判定を続ける。
  }

  const tags = navigator.languages?.length ? navigator.languages : [navigator.language]
  for (const tag of tags) {
    const code = String(tag ?? '').toLowerCase().split('-')[0]
    if (LOCALES[code]) return code
  }
  return FALLBACK_LANG
}

// storeLang は選択した言語を保存します。保存できない環境では何もしません。
export function storeLang(lang) {
  try {
    localStorage.setItem(STORAGE_KEY, lang)
  } catch {
    // 保存できなくても表示自体は切り替わるため、失敗は無視する。
  }
}

function interpolate(template, params) {
  if (!params) return template
  return template.replace(PLACEHOLDER, (match, name) =>
    Object.hasOwn(params, name) ? String(params[name]) : match,
  )
}

// candidateKeys は参照するキーの候補を優先順に返します。
// params.count がある場合は複数形バリアント（_one / _other）を先に探します。
function candidateKeys(lang, key, params) {
  if (typeof params?.count !== 'number') return [key]
  const category = pluralRules(lang).select(params.count)
  return [`${key}_${category}`, `${key}_other`, key]
}

function lookup(lang, key) {
  const dict = LOCALES[lang]
  if (dict && Object.hasOwn(dict, key)) return dict[key]

  const fallback = LOCALES[FALLBACK_LANG]
  if (fallback && Object.hasOwn(fallback, key)) return fallback[key]

  return null
}

// createTranslator は指定言語の翻訳関数群を生成します。
//
//   - t(key, params)  UIラベルなど、キーを直接指定して訳す
//   - tm(message)     バックエンドが返す {key, params} 形式のメッセージを訳す
//   - formatDate(v)   日付を表示言語の書式に整える
export function createTranslator(lang) {
  const t = (key, params) => {
    if (!key) return ''
    for (const candidate of candidateKeys(lang, key, params)) {
      const template = lookup(lang, candidate)
      if (template !== null) return interpolate(template, params)
    }
    // 辞書に無いキーはそのまま表示し、翻訳漏れに気づけるようにする。
    return key
  }

  const tm = (message) => {
    if (!message) return ''
    // 旧形式（訳文そのまま）のレスポンスを受け取っても壊れないようにしておく。
    if (typeof message === 'string') return message
    return t(message.key, message.params)
  }

  const formatDate = (value) => {
    const date = value instanceof Date ? value : new Date(value)
    if (Number.isNaN(date.getTime())) return ''
    return new Intl.DateTimeFormat(lang, { dateStyle: 'medium' }).format(date)
  }

  return { t, tm, formatDate }
}

export const I18nContext = createContext(null)

// useI18n は表示言語と翻訳関数を取り出します。
export function useI18n() {
  const ctx = useContext(I18nContext)
  if (!ctx) {
    throw new Error('useI18n は <I18nProvider> の内側で呼び出してください')
  }
  return ctx
}
