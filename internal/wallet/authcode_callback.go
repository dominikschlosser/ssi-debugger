package wallet

import (
	"net/url"
)

// RegisterAuthorizationCodeCallback reserves a callback slot for the given state.
// The returned channel receives the eventual redirect query values.
func (w *Wallet) RegisterAuthorizationCodeCallback(state string) (<-chan url.Values, func()) {
	ch := make(chan url.Values, 1)
	w.mu.Lock()
	if w.authCodeCallbacks == nil {
		w.authCodeCallbacks = make(map[string]chan url.Values)
	}
	w.authCodeCallbacks[state] = ch
	w.mu.Unlock()

	return ch, func() {
		w.mu.Lock()
		delete(w.authCodeCallbacks, state)
		w.mu.Unlock()
	}
}

// CompleteAuthorizationCodeCallback delivers the redirect query values to a waiting flow.
func (w *Wallet) CompleteAuthorizationCodeCallback(values url.Values) bool {
	state := values.Get("state")
	if state == "" {
		return false
	}

	w.mu.Lock()
	ch, ok := w.authCodeCallbacks[state]
	if ok {
		delete(w.authCodeCallbacks, state)
	}
	w.mu.Unlock()
	if !ok {
		return false
	}

	select {
	case ch <- values:
	default:
	}
	return true
}
