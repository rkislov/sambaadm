//go:build windows

package main

import "fmt"

func checkHelperConfig(string) error {
	return fmt.Errorf("sambaadm-helper host operations require Linux")
}
