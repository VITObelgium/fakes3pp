package interfaces

import "net/http"

type CORSHandler interface {
	//Sets CORS response headers based on the bucket used in the request
	//On AWS CORS configuration is per bucket hence a bucket is passed on
	//The targetRegion and BackendManager are provided for implementation that would
	//actually resolve the CORS configuration.
	SetHeaders(w http.ResponseWriter, bucket, targetRegion string, bm BackendManager)
}
