package interfaces

import "github.com/VITObelgium/fakes3pp/aws/service/iam"

type PolicyRetriever interface {
	//Takes S3ApiAction and whether it is a presigned request
	GetPolicy(arn string, data *iam.PolicySessionData) (string, error)
}
