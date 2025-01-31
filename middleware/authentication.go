package middleware

import (
	"log/slog"
	"net/http"

	"github.com/VITObelgium/fakes3pp/requestctx"
)

const L_AUTH_TYPE = "AuthType"

//Register an operation into the requestctx such that it can be retrieved by the context
//
func AuthNPresigned() Middleware {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
			requestctx.AddAccessLogInfo(r, "s3", slog.String(L_AUTH_TYPE, "QueryString"))

			// //bool to track whether signature was ok
			// var isValid bool
			// var expires time.Time

			// signingKey, err := getSigningKey()
			// if err != nil {
			// 	slog.ErrorContext(ctx, "Could not get signing key", "error", err)
			// 	writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
			// 	return
			// }

			// var secretDeriver = func(accessKeyId string) (secretAccessKey string, err error) {
			// 	return CalculateSecretKey(accessKeyId, signingKey), nil
			// }

			// presignedUrl, err := presign.MakePresignedUrl(r)
			// if err != nil {
			// 	slog.ErrorContext(ctx, "Could not get presigned url", "error", err)
			// 	writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
			// 	return
			// }
			// isValid, creds, expires, err:= presignedUrl.GetPresignedUrlDetails(ctx, secretDeriver)
			// if err != nil {
			// 	slog.ErrorContext(ctx, "Error geting details of presigned url", "error", err)
			// 	writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
			// 	return
			// }

			// // If url has gone passed expiry time (under user control)
			// if expires.Before(time.Now().UTC()) {
			// 	slog.InfoContext(ctx, "Encountered expired URL", "expires", expires)
			// 	writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, errors.New("expired URL"))
			// 	return
			// }

			// if isValid {
				next.ServeHTTP(w, r)
			// } else {
			// 	slog.InfoContext(ctx, "Invalid S3 signature")
			// 	writeS3ErrorAccessDeniedResponse(ctx, w)
			// 	return
			// }
        }
    }
}

