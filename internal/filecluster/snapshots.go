package filecluster

import "fmt"

type SnapshotPolicy struct {
	Enabled         bool `json:"enabled"`
	IntervalMinutes int  `json:"intervalMinutes"`
	Retain          int  `json:"retain"`
}

func (policy SnapshotPolicy) Validate() error {
	switch policy.IntervalMinutes {
	case 60, 360, 1440:
	default:
		return fmt.Errorf("выберите интервал: час, 6 часов или сутки")
	}
	if policy.Retain < 1 || policy.Retain > 168 {
		return fmt.Errorf("можно хранить от 1 до 168 автоснимков")
	}
	return nil
}

type SnapshotScheduleInput struct {
	ActivationInput
	Policy SnapshotPolicy `json:"policy"`
}
