package web

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sambaadm/internal/filecluster"
)

func (c clusterRPC) updateSchedule(ctx context.Context, ref clusterRef, in filecluster.SnapshotScheduleInput) (map[string]string, error) {
	if err := in.ActivationInput.Validate("snapshot-schedule"); err != nil {
		return nil, err
	}
	if err := in.Policy.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	states, err := c.status(ctx, ref)
	if err != nil {
		return nil, err
	}
	owner, err := snapshotOwner(states)
	if err != nil {
		return nil, err
	}
	if in.Policy.Enabled {
		nodes := make([]filecluster.Node, len(ref.Nodes))
		for i, state := range states {
			if state.Error != "" || state.LocalNode != state.Node {
				return nil, errors.New("для включения автоснимков должны отвечать оба хелпера")
			}
			nodes[i].Name = state.Node
		}
		// Do not enable the shared policy until both persistent timers exist.
		if err = inPair(nodes, func(_ int, node string) error {
			request := in.ActivationInput
			request.RequestID = clusterID()
			var result struct{ Timer string }
			if err := c.job(ctx, node, "filecluster.snapshot-timer", request, &result, func(string) {}); err != nil {
				return err
			}
			if result.Timer == "" {
				return fmt.Errorf("%s не подтвердил установку таймера", node)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		states, err = c.status(ctx, ref)
		if err != nil {
			return nil, err
		}
		owner, err = snapshotOwner(states)
		if err != nil {
			return nil, err
		}
	}
	var job filecluster.JobStatus
	if err = c.call(ctx, owner, "filecluster.snapshot-schedule", in, &job); err != nil {
		return nil, err
	}
	return map[string]string{"node": owner, "id": job.ID}, nil
}
