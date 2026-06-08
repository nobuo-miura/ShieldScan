// Package models はスキャン履歴のデータモデルとインメモリストレージを提供します。
package models

import (
	"sync"
	"time"

	"github.com/nobuo-miura/shieldscan/internal/analyzer"
)

// HistoryEntry は1回のスキャン結果を表します。
// 一覧表示用のサマリーフィールドと、詳細取得用の Result フィールドを持ちます。
// Result は [InMemoryStore.List] では省略され、メモリ効率を保ちます。
type HistoryEntry struct {
	ID         int                      `json:"id"`
	URL        string                   `json:"url"`
	TotalScore int                      `json:"total_score"`
	MaxScore   int                      `json:"max_score"`
	Grade      string                   `json:"grade"`
	ScannedAt  time.Time                `json:"scanned_at"`
	Result     *analyzer.AnalysisResult `json:"result,omitempty"`
}

// InMemoryStore はスキャン履歴をメモリ上に保持するスレッドセーフなストアです。
// 最大50件を保持し、超過した古いエントリーは自動的に削除されます。
type InMemoryStore struct {
	mu      sync.RWMutex
	entries []HistoryEntry
	nextID  int
}

// Store はアプリケーション全体で共有するグローバルなスキャン履歴ストアです。
var Store = &InMemoryStore{nextID: 1}

// Add はスキャン結果を履歴の先頭（最新順）に追加し、保存したエントリーを返します。
// 保持件数が50件を超えた場合、最も古いエントリーを削除します。
// 並行呼び出しに対してスレッドセーフです。
func (s *InMemoryStore) Add(result *analyzer.AnalysisResult) HistoryEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := HistoryEntry{
		ID:         s.nextID,
		URL:        result.URL,
		TotalScore: result.TotalScore,
		MaxScore:   result.MaxScore,
		Grade:      result.Grade,
		ScannedAt:  result.ScannedAt,
		Result:     result,
	}
	s.entries = append([]HistoryEntry{entry}, s.entries...) // prepend (newest first)
	if len(s.entries) > 50 {
		s.entries = s.entries[:50]
	}
	s.nextID++
	return entry
}

// List は保存されている全エントリーのサマリー一覧を返します。
// レスポンスを軽量に保つため、各エントリーの Result フィールドは省略されます。
// 並行呼び出しに対してスレッドセーフです。
func (s *InMemoryStore) List() []HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]HistoryEntry, len(s.entries))
	for i, e := range s.entries {
		list[i] = HistoryEntry{
			ID:         e.ID,
			URL:        e.URL,
			TotalScore: e.TotalScore,
			MaxScore:   e.MaxScore,
			Grade:      e.Grade,
			ScannedAt:  e.ScannedAt,
		}
	}
	return list
}
