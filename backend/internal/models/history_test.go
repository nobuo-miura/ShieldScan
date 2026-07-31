package models

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nobuo-miura/shieldscan/internal/analyzer"
)

func result(url string) *analyzer.AnalysisResult {
	return &analyzer.AnalysisResult{
		URL:        url,
		TotalScore: 75,
		MaxScore:   100,
		Grade:      "B",
		ScannedAt:  time.Now(),
	}
}

func TestAddReturnsNewestFirst(t *testing.T) {
	s := &InMemoryStore{nextID: 1}
	s.Add(result("https://first.example"))
	s.Add(result("https://second.example"))

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("件数 = %d, want 2", len(list))
	}
	if list[0].URL != "https://second.example" {
		t.Errorf("先頭 = %q, 最新のエントリであるべきです", list[0].URL)
	}
}

func TestAddAssignsIncrementingIDs(t *testing.T) {
	s := &InMemoryStore{nextID: 1}
	first := s.Add(result("https://a.example"))
	second := s.Add(result("https://b.example"))

	if first.ID != 1 || second.ID != 2 {
		t.Errorf("ID = %d, %d, want 1, 2", first.ID, second.ID)
	}
}

func TestAddCapsAtMaxEntries(t *testing.T) {
	s := &InMemoryStore{nextID: 1}
	for i := range 60 {
		s.Add(result(fmt.Sprintf("https://%d.example", i)))
	}

	list := s.List()
	if len(list) != 50 {
		t.Fatalf("件数 = %d, want 50", len(list))
	}
	// 最新50件が残っているので、先頭は59番目
	if list[0].URL != "https://59.example" {
		t.Errorf("先頭 = %q, want https://59.example", list[0].URL)
	}
	if list[49].URL != "https://10.example" {
		t.Errorf("末尾 = %q, want https://10.example", list[49].URL)
	}
}

// TestListOmitsResult は、一覧APIが詳細結果を含めないことを確認します。
// 50件分の全ヘッダー結果を返すとレスポンスが不必要に肥大化します。
func TestListOmitsResult(t *testing.T) {
	s := &InMemoryStore{nextID: 1}
	s.Add(result("https://example.com"))

	if got := s.List()[0].Result; got != nil {
		t.Errorf("List() の Result = %v, nil であるべきです", got)
	}
}

// TestConcurrentAccess は -race 付きで実行したときにデータ競合がないことを確認します。
func TestConcurrentAccess(t *testing.T) {
	s := &InMemoryStore{nextID: 1}

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.Add(result(fmt.Sprintf("https://%d.example", i)))
		}()
		go func() {
			defer wg.Done()
			_ = s.List()
		}()
	}
	wg.Wait()

	if got := len(s.List()); got != 50 {
		t.Errorf("件数 = %d, want 50", got)
	}
}
