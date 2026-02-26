package proxy

import "sync"

// Store is a thread-safe ring buffer of traffic entries with SSE broadcast support.
type Store struct {
	mu          sync.RWMutex
	entries     []*TrafficEntry
	maxSize     int
	nextID      int64
	subscribers map[int64]chan *TrafficEntry
	subID       int64
}

// NewStore creates a new store with the given maximum entry count.
func NewStore(maxSize int) *Store {
	return &Store{
		maxSize:     maxSize,
		entries:     make([]*TrafficEntry, 0, maxSize),
		subscribers: make(map[int64]chan *TrafficEntry),
	}
}

// Add stores a traffic entry, evicting the oldest if the buffer is full,
// and notifies all SSE subscribers.
func (s *Store) Add(entry *TrafficEntry) {
	s.mu.Lock()
	s.nextID++
	entry.ID = s.nextID
	if len(s.entries) >= s.maxSize {
		s.entries = s.entries[1:]
	}
	s.entries = append(s.entries, entry)
	// Snapshot subscribers under lock
	subs := make([]chan *TrafficEntry, 0, len(s.subscribers))
	for _, ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	// Notify outside of lock to avoid blocking
	for _, ch := range subs {
		select {
		case ch <- entry:
		default:
			// subscriber too slow, skip
		}
	}
}

// Entries returns a snapshot of all stored entries.
func (s *Store) Entries() []*TrafficEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*TrafficEntry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Subscribe returns a channel that receives new traffic entries and an unsubscribe function.
func (s *Store) Subscribe() (<-chan *TrafficEntry, func()) {
	ch := make(chan *TrafficEntry, 64)
	s.mu.Lock()
	s.subID++
	id := s.subID
	s.subscribers[id] = ch
	s.mu.Unlock()

	unsub := func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
		// Drain channel
		for range ch {
		}
	}
	return ch, unsub
}
