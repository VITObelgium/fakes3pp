package iam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
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

func NewPolicyEvaluator(pol *policy.Policy) *PolicyEvaluator {
	pe := PolicyEvaluator{
		p: pol,
	}
	return &pe
}

func NewPolicyEvaluatorFromStr(policyContent string) (*PolicyEvaluator, error) {
	p, err := parsePolicy(policyContent)
	if err != nil {
		return nil, err
	}
	return NewPolicyEvaluator(p), nil
}

type evalReason string

const reasonActionIsAllowed evalReason = "Action is allowed"
const reasonNoStatementAllowingAction evalReason = "No statement allows the action"
const reasonExplicitDeny evalReason = "Explicit deny"
const reasonErrorEncountered evalReason = "Error was encountered"

// Allow wildcards like * and ? but escape other special characters
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
func iamStringLike(patternString, literalStrin string) bool {
	saferPattern := regexp.QuoteMeta(patternString)
	pattern := strings.NewReplacer("\\*", ".*", "\\?", ".").Replace(saferPattern)
	match, err := regexp.MatchString(pattern, literalStrin)
	if err != nil {
		slog.Error("Error for checking match", "pattern_string", patternString, "pattern", pattern, "literal", literalStrin, "error", err)
	}
	return match
}

// The statement resource can have wildcards like * and ?
// so use the StringLike to check it
func doesResourceMatch(statementResource, resource string) bool {
	return iamStringLike(statementResource, resource)
}

// perValuePredicate returns whether any of the statement patterns matches
// the given (singular) context value. Negation, when needed by *Not* base
// operators, is applied per-value by the dispatcher so that quantifier
// semantics (ForAnyValue/ForAllValues) remain strictly AWS-aligned. The
// error return allows operators like IpAddress to fail evaluation on
// malformed statement patterns (matching AWS "policy syntax error"
// behaviour).
type perValuePredicate func(patterns []string, value string) (bool, error)

func stringEqualsPredicate(patterns []string, value string) (bool, error) {
	for _, p := range patterns {
		if p == value {
			return true, nil
		}
	}
	return false, nil
}

func stringLikePredicate(patterns []string, value string) (bool, error) {
	for _, p := range patterns {
		if iamStringLike(p, value) {
			return true, nil
		}
	}
	return false, nil
}

// ipAddressPredicate matches a context value (an IPv4 or IPv6 address) against
// one or more statement patterns. Each pattern may be either a bare IP address
// (treated as /32 for IPv4 or /128 for IPv6) or a CIDR prefix. Mixed v4/v6
// patterns are supported. An invalid statement pattern produces an error so
// the surrounding policy evaluation fails closed (deny), matching AWS
// "policy syntax error" semantics; an info-level log entry is emitted so
// operators can spot the misconfiguration in the proxy logs.
func ipAddressPredicate(patterns []string, value string) (bool, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		// Context value is not a parseable IP; this should not happen because
		// aws:SourceIp is populated from the request, but be defensive.
		return false, fmt.Errorf("invalid aws:SourceIp value %s: %w", value, err)
	}
	// We iterate over every pattern even if some are malformed so that a
	// single bogus entry in the policy does not mask an otherwise valid
	// match. AWS treats unmatched + erroring as a policy syntax error
	// (deny), but a successful match by any sibling pattern still wins.
	var firstErr error
	for _, p := range patterns {
		prefix, perr := parseIPPattern(p)
		if perr != nil {
			slog.Info("invalid IP pattern in policy condition", "pattern", p, "error", perr)
			if firstErr == nil {
				firstErr = fmt.Errorf("invalid IP pattern %q: %w", p, perr)
			}
			continue
		}
		if prefix.Contains(addr) {
			return true, nil
		}
	}
	if firstErr != nil {
		return false, firstErr
	}
	return false, nil
}

// parseIPPattern accepts either a CIDR ("10.0.0.0/24", "2001:db8::/32") or a
// bare address ("10.0.0.1", "::1") and returns the corresponding prefix.
func parseIPPattern(pattern string) (netip.Prefix, error) {
	if strings.Contains(pattern, "/") {
		return netip.ParsePrefix(pattern)
	}
	addr, err := netip.ParseAddr(pattern)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if addr.Is6() && !addr.Is4In6() {
		bits = 128
	}
	return addr.Prefix(bits)
}

// splitQualifier splits an operator like "ForAnyValue:StringEquals" into
// ("ForAnyValue", "StringEquals"). When no qualifier is present the
// qualifier component is "".
func splitQualifier(operator string) (qualifier, base string) {
	if idx := strings.Index(operator, ":"); idx >= 0 {
		return operator[:idx], operator[idx+1:]
	}
	return "", operator
}

// perValuePredicateFor returns the per-value predicate to apply for a base
// operator together with a flag indicating whether the result of the
// predicate must be negated (for the StringNot* family).
func perValuePredicateFor(baseOp string) (perValuePredicate, bool, error) {
	switch baseOp {
	case "StringEquals":
		return stringEqualsPredicate, false, nil
	case "StringNotEquals":
		return stringEqualsPredicate, true, nil
	case "StringLike":
		return stringLikePredicate, false, nil
	case "StringNotLike":
		return stringLikePredicate, true, nil
	case "IpAddress":
		return ipAddressPredicate, false, nil
	case "NotIpAddress":
		return ipAddressPredicate, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported condition: '%s'", baseOp)
	}
}

// evalConditionKey applies the qualifier and per-value predicate to a single
// condition-key entry. Quantifier semantics follow the AWS IAM reference:
//
//   - unqualified: the context value must be singular (multi-valued context
//     keys are rejected with an error for safety so policies must explicitly
//     opt into ForAnyValue/ForAllValues handling). Missing key => false.
//   - ForAnyValue: at least one context value must satisfy the predicate.
//     Missing key => false.
//   - ForAllValues: every context value must satisfy the predicate.
//     Missing key (or empty set) => vacuously true. Pair with Null:<key>:false
//     when "the key must be present" is required.
//
// For StringNot* base operators the per-value predicate is negated before
// the quantifier is applied (strict AWS semantics, not !ForAnyValue(positive)).
func evalConditionKey(qualifier string, pred perValuePredicate, negate bool, stmtValues *policy.ConditionValue, ctxValues *policy.ConditionValue, key string) (bool, error) {
	patterns, _, _ := stmtValues.Values()
	var values []string
	if ctxValues != nil {
		values, _, _ = ctxValues.Values()
	}

	apply := func(v string) (bool, error) {
		m, err := pred(patterns, v)
		if err != nil {
			return false, err
		}
		if negate {
			return !m, nil
		}
		return m, nil
	}

	switch qualifier {
	case "":
		if len(values) > 1 {
			return false, fmt.Errorf("non-singular value got %v", values)
		}
		if len(values) == 0 {
			slog.Debug("condition key was not set in request context", "conditionKey", key)
			// AWS docs: when the key is absent from the request context and
			// the operator is a *Not* variant the condition is satisfied;
			// positive variants are not.
			// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
			return negate, nil
		}
		return apply(values[0])
	case "ForAnyValue":
		if len(values) == 0 {
			return false, nil
		}
		// A successful match by any value wins, even when other values
		// produced evaluation errors (e.g. a malformed sibling IP pattern
		// inside the same predicate call). Errors are only surfaced when
		// no value matched, so the caller can deny + report the syntax
		// problem instead of silently masking it.
		var firstErr error
		for _, v := range values {
			ok, err := apply(v)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if ok {
				return true, nil
			}
		}
		if firstErr != nil {
			return false, firstErr
		}
		return false, nil
	case "ForAllValues":
		for _, v := range values {
			ok, err := apply(v)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported qualifier: '%s'", qualifier)
	}
}

// evalNull implements the IAM Null operator. The statement value must be a
// single "true" or "false" literal. The condition is met when the
// presence-state of the key in the request context matches the requested
// state. An empty (zero-value) context entry is treated as absent.
func evalNull(conditionDetails map[string]*policy.ConditionValue, context map[string]*policy.ConditionValue) (bool, error) {
	for key, stmtVals := range conditionDetails {
		wants, _, _ := stmtVals.Values()
		if len(wants) != 1 {
			return false, fmt.Errorf("the Null operator for key %s requires a single string value", key)
		}
		var wantNull bool
		switch wants[0] {
		case "true":
			wantNull = true
		case "false":
			wantNull = false
		default:
			return false, fmt.Errorf("the Null operator value must be 'true' or 'false', got %q", wants[0])
		}
		ctxVal, present := context[key]
		if present {
			vals, _, _ := ctxVal.Values()
			if len(vals) == 0 {
				present = false
			}
		}
		isNull := !present
		if isNull != wantNull {
			return false, nil
		}
	}
	return true, nil
}

// evalCondition evaluates a single (operator, conditionDetails) entry from a
// Condition block. Operators may carry the AWS quantifier prefixes
// "ForAnyValue:" or "ForAllValues:" (e.g. "ForAllValues:StringEquals"). The
// "Null" operator does not accept quantifiers. All keys within
// conditionDetails are AND-combined.
func evalCondition(operator string, conditionDetails map[string]*policy.ConditionValue, context map[string]*policy.ConditionValue) (bool, error) {
	qualifier, baseOp := splitQualifier(operator)

	if baseOp == "Null" {
		if qualifier != "" {
			return false, fmt.Errorf("qualifier %s is not valid with Null operator", qualifier)
		}
		return evalNull(conditionDetails, context)
	}

	pred, negate, err := perValuePredicateFor(baseOp)
	if err != nil {
		return false, err
	}

	for key, stmtVals := range conditionDetails {
		ok, err := evalConditionKey(qualifier, pred, negate, stmtVals, context[key], key)
		if err != nil {
			return false, fmt.Errorf("operator %s encountered %s", operator, err)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// EvalConditionBlock evaluates a raw IAM Condition block against a context without
// needing a full policy statement (no action/resource check). All condition operators
// in the block must be satisfied for the result to be true.
// This is used for credential rule selection where we only need predicate evaluation.
func EvalConditionBlock(conditionBlock map[string]map[string]*policy.ConditionValue, context map[string]*policy.ConditionValue) (bool, error) {
	for conditionOperator, conditionDetails := range conditionBlock {
		isMet, err := evalCondition(conditionOperator, conditionDetails, context)
		if err != nil {
			return false, err
		}
		if !isMet {
			return false, nil
		}
	}
	return true, nil
}

// isPrincipalMatch implements a minimal AWS-style Principal check.
//
//   - When the statement does not declare a Principal, it is treated as
//     unconstrained (matches). This preserves the original behavior for
//     permission policies which never carry a Principal.
//   - When the statement uses the string form `"Principal": "*"`, every
//     principal matches.
//   - When the statement uses the object form, entries are matched against
//     the request principal by Kind: a request principal of kind Federated
//     is matched against `statement.Federated()`, an AWS request against
//     `statement.AWS()`, and so on. Patterns support `*`/`?` wildcards via
//     iamStringLike.
//   - The special case `{"AWS": "*"}` is treated as a wildcard for any
//     principal kind (matching the AWS "anonymous" semantics).
//   - When the action carries no Principal value (e.g. permission policies
//     are evaluated without a request principal) only the wildcard forms
//     above match.
func isPrincipalMatch(p *policy.Principal, a IAMAction) bool {
	if p == nil {
		return true
	}
	// String form: "*" is the only legal value.
	if kinds := p.Kinds(); len(kinds) == 1 && kinds[0] == policy.PrincipalKindAll {
		return true
	}
	// Documented AWS wildcard for anonymous principals.
	if aws := p.AWS(); aws != nil {
		for _, pattern := range aws.Values() {
			if pattern == "*" {
				return true
			}
		}
	}
	if a.Principal == nil {
		return false
	}

	var candidates *policy.StringOrSlice
	switch a.Principal.Kind {
	case policy.PrincipalKindFederated:
		candidates = p.Federated()
	case policy.PrincipalKindAWS:
		candidates = p.AWS()
	case policy.PrincipalKindCanonical:
		candidates = p.CanonicalUser()
	case policy.PrincipalKindService:
		candidates = p.Service()
	}
	if candidates == nil {
		return false
	}
	for _, pattern := range candidates.Values() {
		if pattern == a.Principal.Value || iamStringLike(pattern, a.Principal.Value) {
			return true
		}
	}
	return false
}

// Check whether a policy Statement is relevent for a certain IAM action
func isRelevantFor(statement policy.Statement, a IAMAction) (bool, error) {
	if !isPrincipalMatch(statement.Principal, a) {
		return false, nil
	}

	actionInScope := false
	if statement.Action != nil {
		for _, statementAction := range statement.Action.Values() {
			if statementAction == a.Action || iamStringLike(statementAction, a.Action) {
				actionInScope = true
			}
		}
	}
	if !actionInScope {
		return false, nil
	}

	// A nil Resource (field absent from the JSON) is treated as "*" — the
	// normal case for trust policy statements, which don't carry a Resource field.
	resourceInScope := statement.Resource == nil
	if !resourceInScope {
		for _, statementResource := range statement.Resource.Values() {
			if doesResourceMatch(statementResource, a.Resource) {
				resourceInScope = true
			}
		}
	}
	if !resourceInScope {
		return false, nil
	}

	for conditionOperator, conditionDetails := range statement.Condition {
		isMet, err := evalCondition(conditionOperator, conditionDetails, a.Context)
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

func (e *PolicyEvaluator) Evaluate(a IAMAction) (isAllowed bool, reason evalReason, err error) {
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
			relevant, err := isRelevantFor(s, a)
			if err != nil {
				return false, reasonErrorEncountered, err
			}
			if relevant {
				return false, reasonExplicitDeny, err
			}
		}
	}
	return
}

// When evaluating multiple iamActions all must be allowed
func (e *PolicyEvaluator) EvaluateAll(actions []IAMAction) (isAllowed bool, reason evalReason, err error) {
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
