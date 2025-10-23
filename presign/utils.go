package presign

import (
	"strconv"
	"time"
)

func epochStrToTime(in string) (time.Time, error) {
	expiresInt, err := strconv.Atoi(in)
	if err != nil {
		return time.Now(), err
	}
	return time.Unix(int64(expiresInt), 0), nil
}
