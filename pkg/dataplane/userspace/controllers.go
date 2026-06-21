package userspace

import (
	"context"
	"errors"

	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

type userspaceLinkController struct {
	manager *Manager
}

func (c userspaceLinkController) SetDeferWorkers(v bool) {
	if c.manager != nil {
		c.manager.SetDeferWorkers(v)
	}
}

func (c userspaceLinkController) PrepareLinkCycle() {
	if c.manager != nil {
		c.manager.PrepareLinkCycle()
	}
}

func (c userspaceLinkController) NotifyLinkCycle() {
	if c.manager != nil {
		c.manager.NotifyLinkCycle()
	}
}

type userspaceHAOps interface {
	UpdateRGActive(int, bool) error
	UpdateHAWatchdog(int, uint64) error
	UpdateFabricFwd(dataplane.FabricFwdInfo) error
	UpdateFabricFwd1(dataplane.FabricFwdInfo) error
	SyncFabricState()
}

type managerHAOps struct {
	manager *Manager
}

func (o managerHAOps) UpdateRGActive(rgID int, active bool) error {
	if o.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	return o.manager.UpdateRGActive(rgID, active)
}

func (o managerHAOps) UpdateHAWatchdog(rgID int, timestamp uint64) error {
	if o.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	return o.manager.UpdateHAWatchdog(rgID, timestamp)
}

func (o managerHAOps) UpdateFabricFwd(info dataplane.FabricFwdInfo) error {
	if o.manager == nil || o.manager.bpfShim == nil {
		return errors.New("nil userspace dataplane")
	}
	return o.manager.bpfShim.UpdateFabricFwd(info)
}

func (o managerHAOps) UpdateFabricFwd1(info dataplane.FabricFwdInfo) error {
	if o.manager == nil || o.manager.bpfShim == nil {
		return errors.New("nil userspace dataplane")
	}
	return o.manager.bpfShim.UpdateFabricFwd1(info)
}

func (o managerHAOps) SyncFabricState() {
	if o.manager != nil {
		o.manager.SyncFabricState()
	}
}

type userspaceHAController struct {
	manager userspaceHAOps
}

func (c userspaceHAController) SetRGActive(ctx context.Context, rgID int, active bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	return c.manager.UpdateRGActive(rgID, active)
}

func (c userspaceHAController) SetHAWatchdog(ctx context.Context, rgID int, timestamp uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	return c.manager.UpdateHAWatchdog(rgID, timestamp)
}

func (c userspaceHAController) SetFabricForwarding(ctx context.Context, id dataplane.FabricID, info dataplane.FabricFwdInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	var err error
	if id == 1 {
		err = c.manager.UpdateFabricFwd1(info)
	} else {
		err = c.manager.UpdateFabricFwd(info)
	}
	if err != nil {
		return err
	}
	// The map update is committed at this point. Always push helper fabric
	// state after a successful fabric0 or fabric1 update so RuntimeDataPlane.HA
	// preserves the same "fresh helper view" contract for every fabric slot.
	c.manager.SyncFabricState()
	return nil
}

func (c userspaceHAController) SyncFabricState(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.manager == nil {
		return errors.New("nil userspace dataplane")
	}
	c.manager.SyncFabricState()
	return nil
}

type userspaceSessionStore struct {
	dataplane.SessionStore
	source dpruntime.SessionDeltaSource
}

func (s userspaceSessionStore) SessionDeltas() dpruntime.SessionDeltaSource {
	return s.source
}
