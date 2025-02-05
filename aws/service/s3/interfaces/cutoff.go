package interfaces

import "time"

type CutoffDecider interface {
	GetCutoffForPresignedUrl() time.Time
}