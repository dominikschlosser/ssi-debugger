//go:build linux

package wallet

import "fmt"

// RegisterURLSchemes is not yet supported on Linux.
// macOS is the only supported platform for URL scheme registration.
func RegisterURLSchemes(listenerPort int) error {
	return fmt.Errorf("URL scheme registration is currently only supported on macOS.\n\nOn Linux, use 'wallet accept <uri>' instead.")
}

// UnregisterURLSchemes is not yet supported on Linux.
func UnregisterURLSchemes() error {
	return fmt.Errorf("URL scheme unregistration is currently only supported on macOS")
}
