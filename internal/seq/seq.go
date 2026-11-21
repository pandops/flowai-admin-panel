// Package seq allocates admin-panel's publisher_seq without storage: the
// counter starts at the process start time in Unix microseconds and every
// message takes max(previous + 1, now in Unix microseconds), so the
// sequence keeps increasing across restarts.
package seq

import (
	"sync"
	"time"
)

// Counter is safe for concurrent use.
type Counter struct {
	mu   sync.Mutex
	last int64
	now  func() time.Time
}

// New starts the counter at now() in Unix microseconds.
func New(now func() time.Time) *Counter { return &Counter{last: now().UnixMicro(), now: now} }

// Next returns the next publisher_seq.
func (c *Counter) Next() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.last + 1
	if t := c.now().UnixMicro(); t > n {
		n = t
	}
	c.last = n
	return n
}
