package service

import (
	"context"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

type HostSample struct {
	Time   int64    `json:"time"`
	CPU    *float64 `json:"cpu"`
	Memory *float64 `json:"memory"`
	Disk   *float64 `json:"disk"`
	Errors []string `json:"errors"`
}
type HostMetrics struct {
	Host     string       `json:"host"`
	OS       string       `json:"os"`
	CPUs     int          `json:"cpus"`
	DiskPath string       `json:"diskPath"`
	Samples  []HostSample `json:"samples"`
}
type HostMonitor struct {
	mu       sync.Mutex
	samples  []HostSample
	previous *cpu.TimesStat
	last     time.Time
}

func cpuUsage(before, after cpu.TimesStat) *float64 {
	total := func(t cpu.TimesStat) float64 {
		return t.User + t.System + t.Idle + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal
	}
	delta := total(after) - total(before)
	idle := after.Idle + after.Iowait - before.Idle - before.Iowait
	if delta <= 0 || idle < 0 {
		return nil
	}
	v := (delta - idle) / delta * 100
	if v < 0 || v > 100 {
		return nil
	}
	return &v
}
func (m *HostMonitor) Snapshot(ctx context.Context) HostMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	root := "/"
	if runtime.GOOS == "windows" {
		root = os.Getenv("SystemDrive") + "\\"
	}
	if len(m.samples) == 0 || now.Sub(m.last) >= 5*time.Second {
		sample := HostSample{Time: now.UnixMilli(), Errors: []string{}}
		times, e := cpu.TimesWithContext(ctx, false)
		if e != nil || len(times) == 0 {
			sample.Errors = append(sample.Errors, "CPU unavailable")
			m.previous = nil
		} else {
			if m.previous != nil && now.Sub(m.last) < 30*time.Second {
				sample.CPU = cpuUsage(*m.previous, times[0])
			}
			m.previous = &times[0]
		}
		if v, e := mem.VirtualMemoryWithContext(ctx); e == nil {
			sample.Memory = &v.UsedPercent
		} else {
			sample.Errors = append(sample.Errors, "memory unavailable")
		}
		if v, e := disk.UsageWithContext(ctx, root); e == nil {
			sample.Disk = &v.UsedPercent
		} else {
			sample.Errors = append(sample.Errors, "disk unavailable")
		}
		m.samples = append(m.samples, sample)
		if len(m.samples) > 120 {
			m.samples = append([]HostSample(nil), m.samples[len(m.samples)-120:]...)
		}
		m.last = now
	}
	host, _ := os.Hostname()
	return HostMetrics{Host: host, OS: runtime.GOOS, CPUs: runtime.NumCPU(), DiskPath: root, Samples: append([]HostSample(nil), m.samples...)}
}
