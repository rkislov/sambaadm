package service

import "context"

type hostTargetKey struct{}

// WithHostNode selects a registered helper for this request without changing global configuration.
func WithHostNode(ctx context.Context, node string) context.Context {
	return context.WithValue(ctx, hostTargetKey{}, node)
}
func HostNode(ctx context.Context, fallback string) string {
	if node, ok := ctx.Value(hostTargetKey{}).(string); ok && node != "" {
		return node
	}
	return fallback
}
