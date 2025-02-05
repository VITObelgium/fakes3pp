package interfaces

import (
	"net/http"

	"github.com/VITObelgium/fakes3pp/aws/service/iam/interfaces"
	"github.com/VITObelgium/fakes3pp/utils"
)


type HandlerBuilderI interface {
	//Takes S3ApiAction and whether it is a presigned request
	Build(bool, BackendManager, interfaces.PolicyRetriever, utils.KeyPairKeeper, CutoffDecider, VirtualHosterIdentifier) http.HandlerFunc
}