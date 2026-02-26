package output

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

// captureOutput captures all terminal output (both fmt and color) during fn execution.
func captureOutput(fn func()) string {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	r, w, _ := os.Pipe()

	oldStdout := os.Stdout
	oldOutput := color.Output
	os.Stdout = w
	color.Output = w

	fn()

	w.Close()
	os.Stdout = oldStdout
	color.Output = oldOutput

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintMapFiltered_HidesX5cByDefault(t *testing.T) {
	m := map[string]any{
		"alg": "ES256",
		"typ": "dc+sd-jwt",
		"x5c": []any{"MIIC...", "MIID..."},
	}

	out := captureOutput(func() {
		printMapFiltered(m, 1, false, "x5c")
	})

	if strings.Contains(out, "MIIC") {
		t.Error("x5c certificate data should be hidden when not verbose")
	}
	if !strings.Contains(out, "x5c: (2 entries, use -v to show)") {
		t.Error("expected x5c summary line")
	}
	if !strings.Contains(out, "alg: ES256") {
		t.Error("non-hidden keys should still be shown")
	}
}

func TestPrintMapFiltered_ShowsX5cWhenVerbose(t *testing.T) {
	m := map[string]any{
		"alg": "ES256",
		"x5c": []any{"MIIC...", "MIID..."},
	}

	out := captureOutput(func() {
		printMapFiltered(m, 1, true, "x5c")
	})

	if !strings.Contains(out, "MIIC") {
		t.Error("x5c certificate data should be shown in verbose mode")
	}
	if strings.Contains(out, "use -v to show") {
		t.Error("should not show summary hint in verbose mode")
	}
}

func TestPrintMapFiltered_NonArrayHiddenKey(t *testing.T) {
	m := map[string]any{
		"alg":    "ES256",
		"secret": "hidden-string",
	}

	out := captureOutput(func() {
		printMapFiltered(m, 1, false, "secret")
	})

	if strings.Contains(out, "hidden-string") {
		t.Error("hidden non-array key should not show its value")
	}
	// Non-array hidden keys are silently omitted (no summary line)
	if strings.Contains(out, "secret") {
		t.Error("non-array hidden key should be silently omitted")
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })

	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"future 13 days", now.Add(13 * 24 * time.Hour), "in 13 days"},
		{"past 1 day", now.Add(-24 * time.Hour), "1 day ago"},
		{"past 3 days", now.Add(-3 * 24 * time.Hour), "3 days ago"},
		{"future 2 hours", now.Add(2 * time.Hour), "in 2 hours"},
		{"future 1 hour", now.Add(1 * time.Hour), "in 1 hour"},
		{"future 90 days", now.Add(90 * 24 * time.Hour), "in 3 months"},
		{"past 60 days", now.Add(-60 * 24 * time.Hour), "2 months ago"},
		{"future 30 minutes", now.Add(30 * time.Minute), "in 30 minutes"},
		{"past 30 seconds", now.Add(-30 * time.Second), "1 minute ago"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relativeTime(tt.t)
			if got != tt.want {
				t.Errorf("relativeTime() = %q, want %q", got, tt.want)
			}
		})
	}
}
