package interfaces

import (
	"net/http"
)


type HandlerBuilderI interface {
	//Takes S3ApiAction and whether it is a presigned request
	Build(BackendManager, CORSHandler) http.HandlerFunc
}