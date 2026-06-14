package ed2ksrv

import (
	"sync"
	"time"
)

// udpLimiter is a per-source-IP token bucket guarding the UDP service. The UDP
// sender address is unauthenticated and trivially spoofable, so this only damps
// per-IP volume; it is not a security boundary on its own.
type udpLimiter struct {
	rate  float64 // tokens (packets) per second, also the burst size
	mu    sync.Mutex
	seen  map[string]*udpBucket
	clock func() time.Time
}

type udpBucket struct {
	tokens float64
	last   time.Time
}

// udpLimiterMaxEntries caps the tracking map so a flood of spoofed source IPs
// cannot grow it without bound; the table is swept when it crosses this size.
const udpLimiterMaxEntries = 65536

func newUDPLimiter(packetsPerSecond int) *udpLimiter {
	if packetsPerSecond <= 0 {
		packetsPerSecond = 20
	}
	return &udpLimiter{
		rate:  float64(packetsPerSecond),
		seen:  make(map[string]*udpBucket),
		clock: time.Now,
	}
}

// allow reports whether a packet from ip may be processed now, consuming one
// token if so.
func (l *udpLimiter) allow(ip string) bool {
	if l == nil {
		return true
	}
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.seen) >= udpLimiterMaxEntries {
		l.sweepLocked(now)
	}

	bucket := l.seen[ip]
	if bucket == nil {
		// New source starts full, then immediately spends one token.
		l.seen[ip] = &udpBucket{tokens: l.rate - 1, last: now}
		return true
	}
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * l.rate
		if bucket.tokens > l.rate {
			bucket.tokens = l.rate
		}
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

// sweepLocked drops fully-refilled (idle) buckets to bound memory. Callers hold l.mu.
func (l *udpLimiter) sweepLocked(now time.Time) {
	for ip, bucket := range l.seen {
		refilled := bucket.tokens + now.Sub(bucket.last).Seconds()*l.rate
		if refilled >= l.rate {
			delete(l.seen, ip)
		}
	}
}
