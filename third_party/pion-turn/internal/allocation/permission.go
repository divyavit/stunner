// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package allocation

import (
	"net"
	"time"

	"github.com/pion/logging"
)

const DefaultPermissionTimeout = time.Duration(5) * time.Minute

// DefaultInitialPermissionTimeout is the lifetime of a permission installed by the
// EventHandler.InitialPermissions callback at allocation time. It is deliberately much shorter
// than DefaultPermissionTimeout: it only has to cover the ICE connectivity-check phase. A client
// that actually relays through the allocation refreshes the permission via CreatePermission or
// ChannelBind; one that never does loses it.
const DefaultInitialPermissionTimeout = 15 * time.Second

// Permission represents a TURN permission. TURN permissions mimic the address-restricted
// filtering mechanism of NATs that comply with [RFC4787].
// See: https://tools.ietf.org/html/rfc5766#section-2.3
type Permission struct {
	Addr          net.Addr
	allocation    *Allocation
	timeout       time.Duration
	lifetimeTimer *time.Timer
	log           logging.LeveledLogger
}

// NewPermission create a new Permission.
func NewPermission(addr net.Addr, log logging.LeveledLogger, timeout time.Duration) *Permission {
	return &Permission{
		Addr:    addr,
		log:     log,
		timeout: timeout,
	}
}

func (p *Permission) start(lifetime time.Duration) {
	p.lifetimeTimer = time.AfterFunc(lifetime, func() {
		p.allocation.RemovePermission(p.Addr)
	})
}

func (p *Permission) refresh(lifetime time.Duration) {
	if !p.lifetimeTimer.Reset(lifetime) {
		p.log.Errorf("Failed to reset permission timer for %v %v", p.Addr, p.allocation.fiveTuple)
	}
}
