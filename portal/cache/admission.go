package cache

import (
	"context"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
)

const (
	maxConcurrentUploads = 2
	maxQueuedUploads     = 32
	uploadQueueTimeout   = 5 * time.Second
)

// Each owner holds at most one active or queued upload. The bounded FIFO
// reserves freed slots for waiting owners before admitting new arrivals.
type uploadWaiter struct {
	owner    types.ServiceIdentityKey
	admitted chan struct{}
}

func (c *Manager) startUpload(ctx context.Context, owner types.ServiceIdentityKey) bool {
	if ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	if _, active := c.uploadActive[owner]; active {
		c.mu.Unlock()
		return false
	}
	for _, waiting := range c.uploadQueue {
		if waiting.owner == owner {
			c.mu.Unlock()
			return false
		}
	}
	if len(c.uploadActive) < maxConcurrentUploads && len(c.uploadQueue) == 0 {
		c.uploadActive[owner] = struct{}{}
		c.mu.Unlock()
		return true
	}
	if len(c.uploadQueue) == maxQueuedUploads {
		c.mu.Unlock()
		return false
	}
	waiter := &uploadWaiter{owner: owner, admitted: make(chan struct{})}
	c.uploadQueue = append(c.uploadQueue, waiter)
	c.mu.Unlock()

	waitCtx, cancel := context.WithTimeout(ctx, uploadQueueTimeout)
	defer cancel()
	select {
	case <-waiter.admitted:
		if ctx.Err() == nil {
			return true
		}
	case <-waitCtx.Done():
	}

	c.mu.Lock()
	if _, admitted := c.uploadActive[owner]; admitted {
		// A grant may race the timeout or cancellation. Hand the slot on.
		delete(c.uploadActive, owner)
		c.advanceUploadsLocked()
	} else {
		for i, queued := range c.uploadQueue {
			if queued == waiter {
				copy(c.uploadQueue[i:], c.uploadQueue[i+1:])
				c.uploadQueue[len(c.uploadQueue)-1] = nil
				c.uploadQueue = c.uploadQueue[:len(c.uploadQueue)-1]
				break
			}
		}
	}
	c.mu.Unlock()
	return false
}

func (c *Manager) finishUpload(owner types.ServiceIdentityKey) {
	c.mu.Lock()
	if _, active := c.uploadActive[owner]; !active {
		c.mu.Unlock()
		panic("cache upload admission released without ownership")
	}
	delete(c.uploadActive, owner)
	c.advanceUploadsLocked()
	c.mu.Unlock()
}

// advanceUploadsLocked transfers capacity directly to the oldest waiter.
func (c *Manager) advanceUploadsLocked() {
	for len(c.uploadActive) < maxConcurrentUploads && len(c.uploadQueue) != 0 {
		waiter := c.uploadQueue[0]
		copy(c.uploadQueue, c.uploadQueue[1:])
		c.uploadQueue[len(c.uploadQueue)-1] = nil
		c.uploadQueue = c.uploadQueue[:len(c.uploadQueue)-1]
		c.uploadActive[waiter.owner] = struct{}{}
		close(waiter.admitted)
	}
}
