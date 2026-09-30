package main

import (
	"context"
	"net"
	"sync"
	"time"
)

// A token bucket used for both directions of traffic. Bytes are reserved
// before a read or write is issued, so the limiter sees the request shape and
// can pace a peer without buffering ahead of the socket.

type rate_limiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second; <= 0 means unlimited
	burst  float64
	tokens float64
	last   time.Time
}

func new_rate_limiter(bytes_per_second int64) *rate_limiter {
	if bytes_per_second <= 0 {
		return &rate_limiter{}
	}
	return &rate_limiter{
		rate:   float64(bytes_per_second),
		burst:  float64(bytes_per_second),
		tokens: float64(bytes_per_second),
		last:   time.Now(),
	}
}

func (r *rate_limiter) enabled() bool {
	return r != nil && r.rate > 0
}

// wait blocks until n bytes of budget are available.
func (r *rate_limiter) wait(ctx context.Context, n int) error {
	if !r.enabled() || n <= 0 {
		return nil
	}

	need := float64(n)
	if need > r.burst {
		need = r.burst
	}

	for {
		r.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(r.last).Seconds()
		r.last = now
		r.tokens += elapsed * r.rate
		if r.tokens > r.burst {
			r.tokens = r.burst
		}
		if r.tokens >= need {
			r.tokens -= need
			r.mu.Unlock()
			return nil
		}
		deficit := need - r.tokens
		delay := time.Duration(deficit / r.rate * float64(time.Second))
		r.mu.Unlock()

		if delay < time.Millisecond {
			delay = time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// throttled_conn paces a peer connection in both directions. It embeds
// net.Conn so the rest of the client is unaware it is talking to a limiter.
type throttled_conn struct {
	net.Conn
	ctx  context.Context
	down *rate_limiter
	up   *rate_limiter
}

func (c *throttled_conn) Read(p []byte) (int, error) {
	if c.down.enabled() {
		if err := c.down.wait(c.ctx, len(p)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}

func (c *throttled_conn) Write(p []byte) (int, error) {
	if c.up.enabled() {
		if err := c.up.wait(c.ctx, len(p)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(p)
}
