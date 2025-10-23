package iam

import (
	"fmt"

	"github.com/micahhausler/aws-iam-policy/policy"
)

type IAMAction struct {
	Action   string                            `json:"action"`
	Resource string                            `json:"resource"`
	Context  map[string]*policy.ConditionValue `json:"context,omitempty"`
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
