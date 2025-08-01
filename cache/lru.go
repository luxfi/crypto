// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cache

import (
	"container/list"
	"sync"
)

// LRU is a thread-safe least recently used cache with a fixed size.
type LRU[K comparable, V any] struct {
	Size int

	mu       sync.Mutex
	items    map[K]*list.Element
	eviction *list.List
}

// entry is the internal struct stored in the eviction list
type entry[K comparable, V any] struct {
	key   K
	value V
}

// NewLRU creates a new LRU cache with the given size
func NewLRU[K comparable, V any](size int) *LRU[K, V] {
	if size <= 0 {
		size = 1
	}
	return &LRU[K, V]{
		Size:     size,
		items:    make(map[K]*list.Element),
		eviction: list.New(),
	}
}

// Put adds or updates a key-value pair in the cache
func (c *LRU[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key already exists
	if elem, ok := c.items[key]; ok {
		// Update value and move to front
		c.eviction.MoveToFront(elem)
		elem.Value.(*entry[K, V]).value = value
		return
	}

	// Add new entry
	elem := c.eviction.PushFront(&entry[K, V]{key: key, value: value})
	c.items[key] = elem

	// Evict oldest if over capacity
	if c.eviction.Len() > c.Size {
		oldest := c.eviction.Back()
		if oldest != nil {
			c.eviction.Remove(oldest)
			delete(c.items, oldest.Value.(*entry[K, V]).key)
		}
	}
}

// Get retrieves a value from the cache
func (c *LRU[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var zero V
	elem, ok := c.items[key]
	if !ok {
		return zero, false
	}

	// Move to front (mark as recently used)
	c.eviction.MoveToFront(elem)
	return elem.Value.(*entry[K, V]).value, true
}

// Evict removes a key from the cache
func (c *LRU[K, V]) Evict(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.eviction.Remove(elem)
		delete(c.items, key)
	}
}

// Flush removes all entries from the cache
func (c *LRU[K, V]) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[K]*list.Element)
	c.eviction.Init()
}

// Len returns the number of items in the cache
func (c *LRU[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.items)
}