package s3

import (
	"net/http"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
)

// An implementation that allows to define static rules for CORS
// these will be shared for all requests so no smart per bucket policies
type corsStatic struct {
	accessControlAllowOrigin string
}


func (c corsStatic) SetHeaders(w http.ResponseWriter, bucket, targetRegion string, bm interfaces.BackendManager) {
	if c.accessControlAllowOrigin != "" {
		w.Header().Add("Access-Control-Allow-Origin", c.accessControlAllowOrigin)
	}
}

type corsStaticOptFunc func(*corsStatic) ()

func NewCORSStatic(optFuncs... corsStaticOptFunc) interfaces.CORSHandler {
	var corsStaticCfg = corsStatic{}
	for _, optFunc := range optFuncs {
		optFunc(&corsStaticCfg)
	}
	return &corsStaticCfg
}

func WithAllowedOrigin(allowedOrigin string) corsStaticOptFunc {
	return func(c *corsStatic) {
		c.accessControlAllowOrigin = allowedOrigin
	}
}

