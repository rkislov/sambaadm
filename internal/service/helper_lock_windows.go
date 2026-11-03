//go:build windows

package service

import (
	"context"
	"fmt"
)

func lockHelper(context.Context, string) (func(), error) {
	return nil, fmt.Errorf("host helper requires Linux")
}
