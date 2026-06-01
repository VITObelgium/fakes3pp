package iam

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/micahhausler/aws-iam-policy/policy"
)

type IAMAction struct {
	Action   string                            `json:"action"`
	Resource string                            `json:"resource"`
	Context  map[string]*policy.ConditionValue `json:"context,omitempty"`
	// Principal, when non-nil, is the concrete identity making the request.
	// It is used during evaluation to match against a statement's
	// `Principal` element. A request principal is, by definition, a single
	// value of a single kind (the asymmetric counterpart to the statement
	// Principal which is a multi-valued pattern).
	Principal *RequestPrincipal `json:"principal,omitempty"`
}

// RequestPrincipal identifies the caller making a request being evaluated.
// It is intentionally a small typed value rather than the parser type
// `policy.Principal`: the parser type models the multi-valued pattern that
// appears in a statement, while a request principal is always one value of
// one kind. Kind matches the constants exposed by the policy package
// (policy.PrincipalKindAWS, policy.PrincipalKindFederated, ...).
type RequestPrincipal struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// NewFederatedRequestPrincipal builds a request principal representing an
// identity federated through an OIDC issuer.
func NewFederatedRequestPrincipal(issuer string) *RequestPrincipal {
	return &RequestPrincipal{Kind: policy.PrincipalKindFederated, Value: issuer}
}

// IAMActionSourceIPKey is the AWS-style request context key for the IP
// address the request originated from. It is populated by callers via
// WithSourceIP so that policies authored with the `IpAddress` /
// `NotIpAddress` condition operators can reason about the caller.
const IAMActionSourceIPKey = "aws:SourceIp"

// WithSourceIP returns the action with `aws:SourceIp` added to its
// evaluation context when sourceIP is non-empty. The source IP is plumbed
// separately from PolicySessionData / TrustPolicySessionData so that it
// remains invisible to the policy template engine; only the policy
// evaluator sees it.
func WithSourceIP(a IAMAction, sourceIP string) IAMAction {
	if sourceIP == "" {
		return a
	}
	if a.Context == nil {
		a.Context = map[string]*policy.ConditionValue{}
	}
	a.Context[IAMActionSourceIPKey] = policy.NewConditionValueString(true, sourceIP)
	return a
}

func NewIamAction(action, resource string, session *PolicySessionData) IAMAction {
	context := map[string]*policy.ConditionValue{}
	addGenericSessionContextKeys(context, session)

	return IAMAction{
		Action:   action,
		Resource: resource,
		Context:  context,
	}
}

// NewAssumeRoleWithWebIdentityIAMAction builds an IAMAction that represents a
// request to assume the given role via AssumeRoleWithWebIdentity. The supplied
// TrustPolicySessionData is used to populate the request context keys that are
// available for trust policy evaluation (AWS-style `<issuer-host>:<claim>` keys,
// `aws:PrincipalTag/*`, `sts:RoleSessionName`, `sts:DurationSeconds`, ...).
func NewAssumeRoleWithWebIdentityIAMAction(roleArn string, d *TrustPolicySessionData) IAMAction {
	context := map[string]*policy.ConditionValue{}
	addTrustSessionContextKeys(context, d)

	var principal *RequestPrincipal
	if d != nil && d.Claims.Issuer != "" {
		principal = NewFederatedRequestPrincipal(d.Claims.Issuer)
	}

	return IAMAction{
		Action:    "sts:AssumeRoleWithWebIdentity",
		Resource:  roleArn,
		Context:   context,
		Principal: principal,
	}
}

// For a given IAM action add context specific for the action
func (a IAMAction) AddContext(context map[string]*policy.ConditionValue) IAMAction {
	for contextKey, ContextKeyValues := range context {
		a.Context[contextKey] = ContextKeyValues
	}
	return a
}

// Add context keys that are added to nearly all requests that contain information about the current session
func addGenericSessionContextKeys(context map[string]*policy.ConditionValue, session *PolicySessionData) {
	addAwsPrincipalTagConditionKeys(context, session)
	addAwsRequestedRegionConditionKey(context, session)
	addGenericTokenClaims(context, session)
}

// Add aws:PrincipalTag/tag-key keys that are added to nearly all requests that contain information about the current session
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principaltag
func addAwsPrincipalTagConditionKeys(context map[string]*policy.ConditionValue, session *PolicySessionData) {
	if session == nil {
		return
	}
	for tagKey, tagValues := range session.Tags.PrincipalTags {
		context[fmt.Sprintf("aws:PrincipalTag/%s", tagKey)] = policy.NewConditionValueString(true, tagValues...)
	}
}

// Add aws:RequestedRegion key that are added to all requests
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html
func addAwsRequestedRegionConditionKey(context map[string]*policy.ConditionValue, session *PolicySessionData) {
	if session == nil {
		return
	}
	if session.RequestedRegion != "" {
		context["aws:RequestedRegion"] = policy.NewConditionValueString(true, session.RequestedRegion)
	}
}

// Add generic session claims
func addGenericTokenClaims(context map[string]*policy.ConditionValue, session *PolicySessionData) {
	if session == nil {
		return
	}
	if session.Claims.Subject != "" {
		context["claims:sub"] = policy.NewConditionValueString(true, session.Claims.Subject)
	}
	if session.Claims.Issuer != "" {
		context["claims:iss"] = policy.NewConditionValueString(true, session.Claims.Issuer)
	}
}

// IssuerHost derives the AWS-style context-key prefix from an OIDC issuer URL.
// Given "https://accounts.google.com/" it returns "accounts.google.com". If the
// issuer is not a parseable URL with a host the issuer string itself is
// returned so policies can still match on it.
func IssuerHost(issuer string) string {
	if issuer == "" {
		return ""
	}
	u, err := url.Parse(issuer)
	if err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	return issuer
}

// Add context keys available during trust policy evaluation.
// Mirrors AWS AssumeRoleWithWebIdentity context keys: each OIDC token claim
// is exposed as `<issuer-host>:<claim>` (e.g. `accounts.google.com:sub`). In
// addition the generic `aws:PrincipalTag/*`, `aws:RequestedRegion`,
// `sts:RoleSessionName` and `sts:DurationSeconds` keys are populated when
// available.
func addTrustSessionContextKeys(context map[string]*policy.ConditionValue, d *TrustPolicySessionData) {
	if d == nil {
		return
	}
	// aws:PrincipalTag/*
	for tagKey, tagValues := range d.Tags.PrincipalTags {
		context[fmt.Sprintf("aws:PrincipalTag/%s", tagKey)] = policy.NewConditionValueString(true, tagValues...)
	}
	if d.RequestedRegion != "" {
		context["aws:RequestedRegion"] = policy.NewConditionValueString(true, d.RequestedRegion)
	}
	if d.RoleSessionName != "" {
		context["sts:RoleSessionName"] = policy.NewConditionValueString(true, d.RoleSessionName)
	}
	if d.DurationSeconds > 0 {
		context["sts:DurationSeconds"] = policy.NewConditionValueString(true, strconv.Itoa(d.DurationSeconds))
	}

	// Per-claim AWS-style keys (`<issuer-host>:<claim>`)
	prefix := IssuerHost(d.Claims.Issuer)
	if prefix == "" {
		return
	}
	if d.Claims.Subject != "" {
		context[fmt.Sprintf("%s:sub", prefix)] = policy.NewConditionValueString(true, d.Claims.Subject)
	}
	if d.Claims.Issuer != "" {
		context[fmt.Sprintf("%s:iss", prefix)] = policy.NewConditionValueString(true, d.Claims.Issuer)
	}
	auds := make([]string, 0, len(d.Claims.Audience))
	for _, aud := range d.Claims.Audience {
		if aud != "" {
			auds = append(auds, aud)
		}
	}
	if len(auds) > 0 {
		// singular=false when the token carries multiple audiences so the
		// underlying ConditionValue is truthfully multi-valued; policies must
		// then use ForAnyValue:/ForAllValues: qualifiers to match.
		key := fmt.Sprintf("%s:aud", prefix)
		context[key] = policy.NewConditionValueString(len(auds) == 1, auds...)
	}
}
