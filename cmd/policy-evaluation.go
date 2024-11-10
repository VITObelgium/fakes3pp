package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/micahhausler/aws-iam-policy/policy"
)

func parsePolicy(policyContent string) (*policy.Policy, error) {
	var p policy.Policy
	decoder := json.NewDecoder(bytes.NewReader([]byte(policyContent)))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

type PolicyEvaluator struct {
	p *policy.Policy
}

func NewPolicyEvaluator(pol *policy.Policy) (*PolicyEvaluator) {
	pe := PolicyEvaluator{
		p: pol,
	}
	return &pe
}

func NewPolicyEvaluatorFromStr(policyContent string)  (*PolicyEvaluator, error) {
	p, err := parsePolicy(policyContent)
	if err != nil {
		return nil, err
	}
	return NewPolicyEvaluator(p), nil
}

type evalReason string
const reasonActionIsAllowed evalReason = "Action is allowed"
const reasonNoStatementAllowingAction evalReason = "No statement allows the action"

//Allow wildcards like * and ? but escape other special characters
//https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
func iamStringLike(patternString, literalStrin string) bool {
	saferPattern := regexp.QuoteMeta(patternString)
	pattern := strings.NewReplacer("\\*", ".*", "\\?", ".").Replace(saferPattern)
	match, err := regexp.MatchString(pattern, literalStrin)
	if err != nil {
		slog.Error("Error for checking match", "pattern_string", patternString, "pattern", pattern, "literal", literalStrin, "error", err)
	}
	return match
}

//The statement resource can have wildcards like * and ?
//so use the StringLike to check it
func doesResourceMatch(statementResource, resource string) bool {
	return iamStringLike(statementResource, resource)
}

//To check whether all the values in the passed context are singular depending on the
//condition operator this might be necessary
func areAllConditionValuesSingular(context map[string]*policy.ConditionValue) (bool) {
	for _, value := range context {
		if !value.IsSingular() {
			return false
		}
	}
	return true
}

// See whether the condition defined by the conditionOperator and conditionDetails is met
// for the given context
func isConditionMetForOperator(conditionOperator string, conditionDetails map[string]*policy.ConditionValue, context map[string]*policy.ConditionValue) (bool, error) {
	switch conditionOperator {
	case "StringLike":
		if !areAllConditionValuesSingular(context) {
			return false, fmt.Errorf("non-singular value for %s, got %v", conditionOperator, context)
		}
		for sConditionKey, sConditionValue := range conditionDetails {
			contextValue, exists := context[sConditionKey]
			if !exists {
				return false, fmt.Errorf("condition key '%s' was not set in request context", sConditionKey)
			}
			if !isConditionMetForStringLike(sConditionValue, contextValue) {
				return false, nil
			}
		}
	default:
		return false, fmt.Errorf("unsupported condition: '%s'", conditionOperator)
	}
	//No unmet condition
	return true, nil
}


func isConditionMetForStringLike(statementValues, context *policy.ConditionValue) (bool) {
	ctxStrValues, _, _ := context.Values()
	ctxStrValue := ctxStrValues[0]
	strValues, _, _ := statementValues.Values()
	for _, sValue := range strValues {
		if iamStringLike(sValue, ctxStrValue) {
			return true
		}
	}
	return false
}

//Check whether a policy Statement is relevent for a certain IAM action
func isRelevantFor(statement policy.Statement, a iamAction) (bool, error) {
	actionInScope := false
	for _, statementAction := range statement.Action.Values() {
		if statementAction == a.Action || iamStringLike(statementAction, a.Action){
			actionInScope = true
		}
	}
	if ! actionInScope {
		return false, nil
	}

	resourceInScope := false
	for _, statementResource := range statement.Resource.Values() {
		if doesResourceMatch(statementResource, a.Resource) {
			resourceInScope = true
		}
	}
	if ! resourceInScope {
		return false, nil
	}

	for conditionOperator, conditionDetails := range statement.Condition {
		isMet, err := isConditionMetForOperator(conditionOperator, conditionDetails, a.Context)
		if err != nil {
			return false, err
		}
		if !isMet {
			//Unmet condition so we are not relevant
			return false, nil
		}
	}

	return true, nil
}

func (e *PolicyEvaluator) Evaluate(a iamAction) (isAllowed bool, reason evalReason, err error) {
	isAllowed = false
	reason = reasonNoStatementAllowingAction
	pol := e.p
	for _, s := range pol.Statements.Values() {
		switch s.Effect {
		case policy.EffectAllow:
			relevant, err := isRelevantFor(s, a)
			if err != nil {
				return false, reasonNoStatementAllowingAction, err
			}
			if relevant {
				isAllowed = true
				reason = reasonActionIsAllowed
			}
		case policy.EffectDeny:
			panic("Not implemented yet")
		}
	}
	return
}

//When evaluating multiple iamActions all must be allowed
func (e *PolicyEvaluator) EvaluateAll(actions []iamAction) (isAllowed bool, reason evalReason, err error) {
	if len(actions) < 1 {
		return false, reasonNoStatementAllowingAction, errors.New("EvaluateAll must have at least 1 iamAction")
	}
	for _, action := range actions {
		isAllowed, reason, err = e.Evaluate(action)
		if err != nil || !isAllowed {
			return
		}
	}
	return
}