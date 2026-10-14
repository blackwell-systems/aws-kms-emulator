package storage

import (
	"errors"
	"testing"
)

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// The server validates PendingWindowInDays before the store sees it, so the
// store's own check is only reachable here.
func TestScheduleKeyDeletion_WindowBounds(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, days := range []int{-1, 1, 6, 31, 365} {
		m, err := s.CreateKey(CreateKeyParams{Spec: "ECC_NIST_P256", Usage: "SIGN_VERIFY"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ScheduleKeyDeletion(m.KeyID, days); code(err) != CodeValidation {
			t.Errorf("window %d: %v, want ValidationException", days, err)
		}
	}
	for days, want := range map[int]int{0: 30, 7: 7, 30: 30} {
		m, _ := s.CreateKey(CreateKeyParams{Spec: "ECC_NIST_P256", Usage: "SIGN_VERIFY"})
		res, err := s.ScheduleKeyDeletion(m.KeyID, days)
		if err != nil || res.WindowInDays != want {
			t.Errorf("window %d: %+v, %v; want %d days", days, res, err, want)
		}
	}
}
