// Package retention implements the relay side of op-log pruning: PROTOCOL.md §4.4 ("Relay MAY
// prune ops with cursor ≤ coversUpTo 30 days after a snapshot exists") gated by §8.1's per-tier
// opRetentionDays policy. Limits are relay-local (ADR-0010), never part of the signed log, so
// this package only ever deletes rows this relay's own store holds - it has no effect on the
// membership log or on any other relay a room might also be synced through.
package retention

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/squaddle-org/relay/internal/limits"
	"github.com/squaddle-org/relay/internal/store"
)

// snapshotMinAge is PROTOCOL.md §4.4's floor, independent of any tier's opRetentionDays: a
// snapshot must have existed for at least this long before the ops it covers become eligible for
// pruning at all, so a client that hasn't been online in a while still has a window to pull it.
const snapshotMinAge = 30 * 24 * time.Hour

// DefaultInterval is how often cmd/relay runs Run in the background.
const DefaultInterval = time.Hour

// Run prunes ops across every room that has a snapshot old enough to satisfy snapshotMinAge,
// deleting ops covered by that snapshot (cursor <= its coversUpTo) that are also older than the
// room's resolved opRetentionDays (§8.1). A nil OpRetentionDays (unlimited/boosted, and every
// room on a self-hosted "-limits=none" relay) means never prune. Returns the total number of ops
// deleted across all rooms.
func Run(st *store.Store, policy *limits.Policy, now time.Time) (int64, error) {
	roomIDs, err := st.ListRoomIDs()
	if err != nil {
		return 0, err
	}

	var pruned int64
	for _, room := range roomIDs {
		coversUpTo, createdAt, err := st.LatestSnapshotMeta(room)
		if err != nil {
			if errors.Is(err, store.ErrSnapshotNotFound) {
				continue
			}
			return pruned, err
		}
		if now.Sub(time.Unix(createdAt, 0)) < snapshotMinAge {
			continue
		}

		rl, err := limits.Resolve(st, room, policy, now.Unix())
		if err != nil {
			return pruned, err
		}
		if rl.OpRetentionDays == nil {
			continue
		}
		cutoff := now.Add(-time.Duration(*rl.OpRetentionDays) * 24 * time.Hour).Unix()

		n, err := st.PruneOpsUpTo(room, coversUpTo, cutoff)
		if err != nil {
			return pruned, err
		}
		pruned += n
	}
	return pruned, nil
}

// StartPeriodic runs Run every interval until ctx is cancelled. Best-effort: a failed run is
// logged and retried next tick, never fatal to the relay process.
func StartPeriodic(ctx context.Context, logger *slog.Logger, st *store.Store, policy *limits.Policy, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pruned, err := Run(st, policy, time.Now())
				if err != nil {
					logger.Error("retention: prune failed", "err", err)
					continue
				}
				if pruned > 0 {
					logger.Info("retention: pruned ops", "count", pruned)
				}
			}
		}
	}()
}
