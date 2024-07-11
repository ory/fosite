package oauth2

import (
	"context"
	"fmt"
	_ "unsafe"
)

var _ HMACPrefixFunc = getPrefix

//go:linkname getPrefix
func getPrefix(ctx context.Context, h *HMACSHAStrategy, part string) string {
	return fmt.Sprintf("ory_%s_", part)
}
