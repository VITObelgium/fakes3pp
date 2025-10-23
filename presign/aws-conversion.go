package presign

import (
	"fmt"
	"time"

	"github.com/VITObelgium/fakes3pp/constants"
)

// Convert query parameter like X-Amz-Date=20240914T190903Z
func XAmzDateToTime(XAmzDate string) (time.Time, error) {
	return time.Parse(constants.TimeFormat, XAmzDate)
}

func XAmzExpiryToTime(XAmzDate string, expirySeconds uint) (time.Time, error) {
	t, err := XAmzDateToTime(XAmzDate)
	if expirySeconds < 365*24*3600 {
		expirySeconds64 := int64(expirySeconds)
		return t.Add(time.Duration(expirySeconds64) * time.Second), err
	} else {
		return t, fmt.Errorf("invalid amount of expiry seconds %d", expirySeconds)
	}

}
