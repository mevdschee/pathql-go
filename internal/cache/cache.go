// Package cache provides a small key/value cache abstraction used for rate
// limiting and short-lived auth/JWKS caching. The embedded backend wraps
// github.com/mevdschee/tqmemory.
package cache

import (
	"errors"
	"runtime"
	"time"

	"github.com/mevdschee/tqmemory/pkg/tqmemory"
)

// Cache is the minimal interface the server depends on.
type Cache interface {
	// Increment is a fixed-window atomic counter: it seeds the key (value 0)
	// with ttl on first use, then adds delta, returning the new value.
	Increment(key string, delta uint64, ttl time.Duration) (uint64, error)
	Get(key string) (value []byte, ok bool, err error)
	Set(key string, value []byte, ttl time.Duration) error
	Close() error
}

// embedded is a Cache backed by an in-process tqmemory sharded cache.
type embedded struct {
	sc *tqmemory.ShardedCache
}

// NewEmbedded builds an in-process tqmemory-backed Cache with a memoryMB MiB cap.
func NewEmbedded(memoryMB int) (Cache, error) {
	cfg := tqmemory.DefaultConfig()
	cfg.MaxMemory = int64(memoryMB) << 20
	// Disable the stale window so a key's hard expiry equals its soft expiry.
	// This makes Increment a clean fixed-window counter that resets exactly at
	// ttl rather than at ttl*StaleMultiplier.
	cfg.StaleMultiplier = 0

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	sc, err := tqmemory.NewSharded(cfg, workers)
	if err != nil {
		return nil, err
	}
	return &embedded{sc: sc}, nil
}

// Increment seeds the key with ttl on first use, then adds delta. tqmemory's
// native Increment returns ErrKeyNotFound on a missing key (it does not create
// it), so we Add a "0" seed carrying the window ttl first. Add returns
// ErrKeyExists when the key is already present, which we ignore. Subsequent
// increments preserve the original expiry, giving a correct fixed window.
func (e *embedded) Increment(key string, delta uint64, ttl time.Duration) (uint64, error) {
	if _, err := e.sc.Add(key, []byte("0"), ttl); err != nil && !errors.Is(err, tqmemory.ErrKeyExists) {
		return 0, err
	}
	val, _, err := e.sc.Increment(key, delta)
	if err != nil {
		return 0, err
	}
	return val, nil
}

// Get returns ok=false on a miss (tqmemory reports a miss as ErrKeyNotFound).
func (e *embedded) Get(key string) (value []byte, ok bool, err error) {
	v, _, _, err := e.sc.Get(key)
	if err != nil {
		if errors.Is(err, tqmemory.ErrKeyNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return v, true, nil
}

// Set stores a value with the given ttl.
func (e *embedded) Set(key string, value []byte, ttl time.Duration) error {
	_, err := e.sc.Set(key, value, ttl)
	return err
}

// Close releases the underlying cache workers.
func (e *embedded) Close() error {
	return e.sc.Close()
}
