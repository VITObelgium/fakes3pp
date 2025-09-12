package s3

import (
	"net/http"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
)

// A dummy implementation to not set any CORS headers
type corsDisabled struct {}


func (c corsDisabled) SetHeaders(w http.ResponseWriter, bucket, targetRegion string, bm interfaces.BackendManager) {
	//Do nothing as CORS is disabled
}

func NewCORSDisabled() interfaces.CORSHandler {
	var cd corsDisabled = corsDisabled{}
	return &cd
}

