//go:build !darwin && !linux

package wallet

import "fmt"

// RegisterURLSchemes is not supported on this platform.
func RegisterURLSchemes(listenerPort int) error {
	return fmt.Errorf("URL scheme registration is currently only supported on macOS.\n\nOn other platforms, use 'wallet accept <uri>' instead.")
}

// UnregisterURLSchemes is not supported on this platform.
func UnregisterURLSchemes() error {
	return fmt.Errorf("URL scheme unregistration is currently only supported on macOS")
}
