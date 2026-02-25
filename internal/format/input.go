package format

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

// ReadInput reads credential input from: URL, file path, "-" for stdin, or raw string.
func ReadInput(input string) (string, error) {
	input = strings.TrimSpace(input)

	if input == "-" || input == "" {
		// Read from stdin
		stat, err := os.Stdin.Stat()
		if err != nil {
			return "", fmt.Errorf("cannot read stdin: %w", err)
		}
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return "", fmt.Errorf("no input provided (use a file path, URL, raw string, or pipe to stdin)")
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}

	// Try as URL
	if strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "http://") {
		return fetchURL(input)
	}

	// Try as file path
	if _, err := os.Stat(input); err == nil {
		b, err := os.ReadFile(input)
		if err != nil {
			return "", fmt.Errorf("reading file %s: %w", input, err)
		}
		return strings.TrimSpace(string(b)), nil
	}

	// Treat as raw credential string
	return input, nil
}

func fetchURL(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching %s: HTTP %d", url, resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response from %s: %w", url, err)
	}

	return strings.TrimSpace(string(b)), nil
}
