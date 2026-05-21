// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

import "sync"

// capWorkers clamps the worker count to a sane minimum/maximum. We never
// want to fan out to fewer than 1 goroutine, and beyond ~64 the
// scheduler contention dominates the work.
//
// Lives in a build-tag-free helper file so both the cgo and !cgo
// engines can share it without duplication.
func capWorkers(n int) int {
	if n < 1 {
		return 1
	}
	if n > 64 {
		return 64
	}
	return n
}

// parallelDo dispatches f over indices [0, total) across at most
// workers goroutines. Returns when every index has completed.
//
// Lives in a build-tag-free helper file so both the cgo and !cgo
// engines can share it.
func parallelDo(total, workers int, f func(int)) {
	if total <= 0 {
		return
	}
	if workers < 1 {
		workers = 1
	}
	if workers > total {
		workers = total
	}
	if workers == 1 {
		for i := 0; i < total; i++ {
			f(i)
		}
		return
	}
	var wg sync.WaitGroup
	ch := make(chan int, total)
	for i := 0; i < total; i++ {
		ch <- i
	}
	close(ch)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range ch {
				f(i)
			}
		}()
	}
	wg.Wait()
}
