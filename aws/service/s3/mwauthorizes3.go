package s3

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/VITObelgium/fakes3pp/aws/credentials"
	"github.com/VITObelgium/fakes3pp/aws/service/iam"
	iaminterfaces "github.com/VITObelgium/fakes3pp/aws/service/iam/interfaces"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/api"
	"github.com/VITObelgium/fakes3pp/aws/service/s3/interfaces"
	"github.com/VITObelgium/fakes3pp/middleware"
	"github.com/VITObelgium/fakes3pp/requestctx"
	"github.com/VITObelgium/fakes3pp/usererror"
	"github.com/VITObelgium/fakes3pp/utils"
)

//Authorization middleware is responsible for the following:
//Make sure the action is authorized as per request context
func AWSAuthZS3(keyStorage utils.JWTVerifier, backendManager interfaces.BackendManager, policyRetriever iaminterfaces.PolicyRetriever,
	presignCutoff interfaces.CutoffDecider, vhi interfaces.VirtualHosterIdentifier) middleware.Middleware {
    return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			targetRegion, err := requestctx.GetTargetRegion(r)
			if err != nil {
				writeS3ErrorResponse(r.Context(), w, ErrS3InternalError, errors.New("could not get target region from requestctx"))
				return
			}

			sessionToken, err := requestctx.GetSessionToken(r)
			if err != nil {
				writeS3ErrorResponse(r.Context(), w, ErrS3InternalError, errors.New("could not get session token from requestctx"))
				return
			}
			var maxExpiryTime = time.Now()
			if middleware.IsPresignedAWSRequest(r) {
				maxExpiryTime = presignCutoff.GetCutoffForPresignedUrl()
			}

			if authorizeS3Action(r.Context(), sessionToken, targetRegion, getS3Action(r), w, r, maxExpiryTime, keyStorage, policyRetriever, vhi){
				next(w, r)
			}
		}
	}
}

// Authorize an S3 action
// maxExpiryTime is an upperbound for the expiry of the session token
func authorizeS3Action(ctx context.Context, sessionToken, targetRegion string, action api.S3Operation, w http.ResponseWriter, r *http.Request, 
	maxExpiryTime time.Time, jwtVerifier utils.JWTVerifier, policyRetriever iaminterfaces.PolicyRetriever, vhi interfaces.VirtualHosterIdentifier) (allowed bool) {
	allowed = false
	sessionClaims, err := credentials.ExtractTokenClaims(sessionToken, jwtVerifier.GetJwtKeyFunc())
	if err != nil {
		err := fmt.Errorf("could not get claims from session token: %w", err)
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSecurity, err)
		return
	}
	expiresJwt, err := sessionClaims.GetExpirationTime()
	if err != nil {
		err := fmt.Errorf("could not get expires claim from session token: %w", err)
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSecurity, err)
		return
	}
	if expiresJwt.Time.Before(maxExpiryTime) {
		slog.WarnContext(ctx, "Credentials are passed expiry", "error", err, "claims", sessionClaims, "cutoff", maxExpiryTime, "expires", expiresJwt)
		writeS3ErrorResponse(ctx, w, ErrS3InvalidSignature, usererror.New(errors.New("expired credentials"), "Expired credentials"))
		return
	}

	policySessionData := iam.GetPolicySessionDataFromClaims(sessionClaims)
	policySessionData.RequestedRegion = targetRegion
	policyStr, err := policyRetriever.GetPolicy(sessionClaims.RoleARN, policySessionData)
	if err != nil {
		slog.ErrorContext(ctx, "Could not get policy for temporary credentials", "error", err, "role_arn", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	slog.DebugContext(ctx, "Policy retrieved", "policy", policyStr)
	pe, err := iam.NewPolicyEvaluatorFromStr(policyStr)
	if err != nil {
		slog.ErrorContext(ctx, "Could not create policy generator", "error", err, "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	iamActions, err := newIamActionsFromS3Request(action, r, policySessionData, vhi)
	if err != nil {
		slog.ErrorContext(ctx, "Could not get IAM actions from request", "error", err, "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}
	isAllowed, reason, err := pe.EvaluateAll(iamActions)
	if err != nil {
		slog.ErrorContext(ctx, "Could not evaluate policy", "error", err, "policy", sessionClaims.RoleARN)
		writeS3ErrorResponse(ctx, w, ErrS3InternalError, nil)
		return
	}

	if isAllowed {
		slog.DebugContext(ctx, "Allowed access", "reason", reason)
		return true
	} else {
		slog.DebugContext(ctx, "Denied access", "reason", reason, "actions", iamActions)
		writeS3ErrorResponse(ctx, w, ErrS3AccessDenied, nil)
		return false
	}
}