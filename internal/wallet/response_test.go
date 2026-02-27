package wallet

import (
	"testing"
)

func TestFormatDirectPostResult_Success(t *testing.T) {
	result := &DirectPostResult{
		StatusCode: 200,
	}
	got := FormatDirectPostResult(result)
	if got != "Response: 200" {
		t.Errorf("expected 'Response: 200', got %s", got)
	}
}

func TestFormatDirectPostResult_WithRedirect(t *testing.T) {
	result := &DirectPostResult{
		StatusCode:  200,
		RedirectURI: "https://verifier.example/success",
	}
	got := FormatDirectPostResult(result)
	expected := "Response: 200 → https://verifier.example/success"
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestFormatDirectPostResult_Error(t *testing.T) {
	result := &DirectPostResult{
		StatusCode: 400,
		Body:       `{"error": "invalid_request"}`,
	}
	got := FormatDirectPostResult(result)
	if got != "Response: 400" {
		t.Errorf("expected 'Response: 400', got %s", got)
	}
}
