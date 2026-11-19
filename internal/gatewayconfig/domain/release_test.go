package domain

import (
	"strings"
	"testing"
	"time"
)

func TestANoteIsOneLineOfPlainTextAtMost512Bytes(t *testing.T) {
	for note, ok := range map[string]bool{
		"":                                  true,
		"moving routes":                     true,
		"移动路由":                              true,
		strings.Repeat("x", MaxNoteBytes):   true,
		strings.Repeat("x", MaxNoteBytes+1): false,
		strings.Repeat("备", 171):            false, // 513 字节
		"two\nlines":                        false,
		"tab\there":                         false,
		"bell\a":                            false,
		"del\x7f":                           false,
		"\xff":                              false,
	} {
		if err := ValidateNote(note); (err == nil) != ok {
			t.Errorf("%q：%v", note, err)
		}
	}
}

func TestAPoolNameIsASafeShortToken(t *testing.T) {
	for name, ok := range map[string]bool{"main": true, "pool-1.a_b": true, "": false, "a b": false, "a/b": false, "..": true, strings.Repeat("p", 65): false} {
		if err := ValidatePool(name); (err == nil) != ok {
			t.Errorf("%q：%v", name, err)
		}
	}
}

func TestOnlyTheNewestActiveIsNotSuperseded(t *testing.T) {
	at := time.Now()
	release := func(number uint64, state ReleaseState) Release {
		return Release{Number: number, Steps: []ReleaseStep{{State: StateStaged, At: at}, {State: state, At: at}}}
	}
	derived := DeriveSuperseded([]Release{release(1, StateActive), release(2, StateFailed), release(3, StateActive), release(4, StateUnknown)})
	var shown []string
	for _, r := range derived {
		shown = append(shown, string(r.ShownState()))
	}
	if strings.Join(shown, " ") != "SUPERSEDED FAILED ACTIVE UNKNOWN" || derived[0].SupersededBy != 3 {
		t.Fatalf("%v", shown)
	}
}
