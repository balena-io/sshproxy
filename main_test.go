package main

import (
	"testing"
	"time"
)

func TestParseIdleTimeout(t *testing.T) {
	for value, expected := range map[string]time.Duration{
		"":    0,
		"0":   0,
		"30":  30 * time.Second,
		"30s": 30 * time.Second,
		"5m":  5 * time.Minute,
	} {
		actual, err := parseIdleTimeout(value)
		if err != nil || actual != expected {
			t.Errorf("parseIdleTimeout(%q) = %v, %v; expected %v", value, actual, err, expected)
		}
	}
	if _, err := parseIdleTimeout("soon"); err == nil {
		t.Error(`parseIdleTimeout("soon") should fail`)
	}
}
