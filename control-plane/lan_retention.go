package controlplane

import (
	"context"
	"log"
	"time"
)

const lanFactRetention = 30 * 24 * time.Hour

// RunLanRetention purges expired facts hourly, independently of signaling presence.
func (s *Server) RunLanRetention(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if _, err := s.LAN.PurgeStaleLanFacts(ctx, lanFactRetention); err != nil {
			log.Print("LAN facts retention failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
