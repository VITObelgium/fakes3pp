package s3

import (
	"fmt"
	"net/http"

	"github.com/VITObelgium/fakes3pp/aws/service/s3/api"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/server"
	"github.com/minio/mux"
)

func registerOperation(operation fmt.Stringer) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		requestctx.SetOperation(r, operation)
	}
}

// Register an operation into the requestctx such that it can be retrieved by the context
func RegisterOperation() middleware.Middleware {
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()
	s3Router := router.NewRoute().PathPrefix(server.SlashSeparator).Subrouter()
	s3Router.Methods(http.MethodGet).Queries("list-type", "2").HandlerFunc(registerOperation(api.ListObjectsV2))
	s3Router.Methods(http.MethodGet).Path("/").HandlerFunc(
		registerOperation(api.ListBuckets))
	s3Router.Methods(http.MethodGet).HandlerFunc(
		registerOperation(api.GetObject))
	s3Router.Methods(http.MethodHead).Path("/").HandlerFunc(
		registerOperation(api.HeadBucket))
	s3Router.Methods(http.MethodHead).HandlerFunc(
		registerOperation(api.HeadObject))
	s3Router.Methods(http.MethodPut).Queries("partNumber", "{pn:.*}", "uploadId", "{ui:.*}").HandlerFunc(
		registerOperation(api.UploadPart))
	s3Router.Methods(http.MethodPut).HandlerFunc(
		registerOperation(api.PutObject))

	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html
	s3Router.Methods(http.MethodPost).Queries("uploads", "").HandlerFunc(
		registerOperation(api.CreateMultipartUpload))
	s3Router.Methods(http.MethodPost).Queries("uploadId", "{id:.*}").HandlerFunc(
		registerOperation(api.CompleteMultipartUpload))

	s3Router.Methods(http.MethodDelete).Queries("uploadId", "{id:.*}").HandlerFunc(
		registerOperation(api.AbortMultipartUpload))

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			router.ServeHTTP(w, r)
			next.ServeHTTP(w, r)
		}
	}
}
