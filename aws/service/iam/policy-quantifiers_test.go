package iam

import (
	"testing"

	"github.com/micahhausler/aws-iam-policy/policy"
)

// TestEvalCondition_Quantifiers exercises the ForAnyValue:/ForAllValues:
// qualifier semantics plus the missing-key handling rules documented in the
// AWS IAM policy evaluation reference.
func TestEvalCondition_Quantifiers(t *testing.T) {
	multiVal := policy.NewConditionValueString(false, "a", "b")

	tests := []struct {
		desc    string
		op      string
		stmt    map[string]*policy.ConditionValue
		ctx     map[string]*policy.ConditionValue
		want    bool
		wantErr bool
	}{
		{
			desc: "ForAnyValue:StringEquals one match",
			op:   "ForAnyValue:StringEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "b")},
			ctx:  map[string]*policy.ConditionValue{"k": multiVal},
			want: true,
		},
		{
			desc: "ForAnyValue:StringEquals no match",
			op:   "ForAnyValue:StringEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "c")},
			ctx:  map[string]*policy.ConditionValue{"k": multiVal},
			want: false,
		},
		{
			desc: "ForAnyValue:StringEquals missing key is false",
			op:   "ForAnyValue:StringEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:  map[string]*policy.ConditionValue{},
			want: false,
		},
		{
			desc: "ForAllValues:StringEquals all match",
			op:   "ForAllValues:StringEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(false, "a", "b", "c")},
			ctx:  map[string]*policy.ConditionValue{"k": multiVal},
			want: true,
		},
		{
			desc: "ForAllValues:StringEquals one extra denies",
			op:   "ForAllValues:StringEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:  map[string]*policy.ConditionValue{"k": multiVal},
			want: false,
		},
		{
			desc: "ForAllValues:StringEquals missing key is vacuously true",
			op:   "ForAllValues:StringEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:  map[string]*policy.ConditionValue{},
			want: true,
		},
		{
			desc: "ForAnyValue:StringNotEquals - true when one ctx value is not the pattern",
			op:   "ForAnyValue:StringNotEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:  map[string]*policy.ConditionValue{"k": multiVal},
			want: true, // "b" is not "a"
		},
		{
			desc: "ForAllValues:StringNotEquals - false because 'a' matches the forbidden pattern",
			op:   "ForAllValues:StringNotEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:  map[string]*policy.ConditionValue{"k": multiVal},
			want: false,
		},
		{
			desc: "ForAllValues:StringLike wildcard matches all",
			op:   "ForAllValues:StringLike",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "?")},
			ctx:  map[string]*policy.ConditionValue{"k": multiVal},
			want: true,
		},
		{
			desc:    "ForSomethingElse qualifier errors",
			op:      "ForSomethingElse:StringEquals",
			stmt:    map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:     map[string]*policy.ConditionValue{"k": multiVal},
			wantErr: true,
		},
		{
			desc: "unqualified StringNotEquals on missing key is true (AWS semantics)",
			op:   "StringNotEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:  map[string]*policy.ConditionValue{},
			want: true,
		},
		{
			desc: "unqualified StringEquals on missing key is false",
			op:   "StringEquals",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:  map[string]*policy.ConditionValue{},
			want: false,
		},
		{
			desc:    "unqualified op on multi-valued ctx errors",
			op:      "StringEquals",
			stmt:    map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "a")},
			ctx:     map[string]*policy.ConditionValue{"k": multiVal},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := evalCondition(tc.op, tc.stmt, tc.ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %v got %v", tc.want, got)
			}
		})
	}
}

// TestEvalCondition_Null exercises the Null operator.
func TestEvalCondition_Null(t *testing.T) {
	tests := []struct {
		desc    string
		stmt    map[string]*policy.ConditionValue
		ctx     map[string]*policy.ConditionValue
		want    bool
		wantErr bool
	}{
		{
			desc: "Null:true on absent key is true",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "true")},
			ctx:  map[string]*policy.ConditionValue{},
			want: true,
		},
		{
			desc: "Null:true on present key is false",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "true")},
			ctx:  map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "v")},
			want: false,
		},
		{
			desc: "Null:false on present key is true",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "false")},
			ctx:  map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "v")},
			want: true,
		},
		{
			desc: "Null:false on absent key is false",
			stmt: map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "false")},
			ctx:  map[string]*policy.ConditionValue{},
			want: false,
		},
		{
			desc:    "Null with non-boolean value errors",
			stmt:    map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "maybe")},
			ctx:     map[string]*policy.ConditionValue{},
			wantErr: true,
		},
		{
			desc:    "ForAnyValue:Null is rejected",
			stmt:    map[string]*policy.ConditionValue{"k": policy.NewConditionValueString(true, "true")},
			ctx:     map[string]*policy.ConditionValue{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			op := "Null"
			if tc.desc == "ForAnyValue:Null is rejected" {
				op = "ForAnyValue:Null"
			}
			got, err := evalCondition(op, tc.stmt, tc.ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %v got %v", tc.want, got)
			}
		})
	}
}

// TestEvalConditionBlock_AudienceMatrix covers the 11 scenarios from the
// trust-policy multi-aud spec: five `ForAllValues:StringEquals + Null:false`
// cases and six `ForAnyValue:StringEquals` cases, matching the AWS-documented
// behaviour for multi-valued context keys.
// Implements logic from documentation:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
func TestEvalConditionBlock_AudienceMatrix(t *testing.T) {
	const key = "localhost:aud"
	allowed := []string{"client1", "sts.localhost"}

	// Policy block with ForAllValues + Null:false (used in cases 1..5).
	forAllPlusNull := map[string]map[string]*policy.ConditionValue{
		"ForAllValues:StringEquals": {key: policy.NewConditionValueString(false, allowed...)},
		"Null":                      {key: policy.NewConditionValueString(true, "false")},
	}
	// Policy block with ForAnyValue only (used in cases 6..11).
	forAny := map[string]map[string]*policy.ConditionValue{
		"ForAnyValue:StringEquals": {key: policy.NewConditionValueString(false, allowed...)},
	}

	// ctxWith builds a request context with the given aud values; pass nothing
	// to produce a context where the key is absent.
	ctxWith := func(vals ...string) map[string]*policy.ConditionValue {
		if len(vals) == 0 {
			return map[string]*policy.ConditionValue{}
		}
		return map[string]*policy.ConditionValue{
			key: policy.NewConditionValueString(len(vals) == 1, vals...),
		}
	}

	tests := []struct {
		desc  string
		block map[string]map[string]*policy.ConditionValue
		ctx   map[string]*policy.ConditionValue
		want  bool
	}{
		// ForAllValues + Null:false ------------------------------------------------
		{"1: ForAllValues + Null:false / aud=[client1] -> allow",
			forAllPlusNull, ctxWith("client1"), true},
		{"2: ForAllValues + Null:false / aud=[sts.localhost] -> allow",
			forAllPlusNull, ctxWith("sts.localhost"), true},
		{"3: ForAllValues + Null:false / aud=[client1, sts.localhost] -> allow",
			forAllPlusNull, ctxWith("client1", "sts.localhost"), true},
		{"4: ForAllValues + Null:false / aud=[client1, s3] -> deny (s3 not in allow-list)",
			forAllPlusNull, ctxWith("client1", "s3"), false},
		{"5: ForAllValues + Null:false / aud absent -> deny (Null:false fails)",
			forAllPlusNull, ctxWith(), false},

		// ForAnyValue --------------------------------------------------------------
		{"6:  ForAnyValue / aud=[client1] -> allow",
			forAny, ctxWith("client1"), true},
		{"7:  ForAnyValue / aud=[sts.localhost] -> allow",
			forAny, ctxWith("sts.localhost"), true},
		{"8:  ForAnyValue / aud=[client1, sts.localhost] -> allow",
			forAny, ctxWith("client1", "sts.localhost"), true},
		{"9:  ForAnyValue / aud=[client1, s3] -> allow (client1 matches)",
			forAny, ctxWith("client1", "s3"), true},
		{"10: ForAnyValue / aud=[s3] -> deny",
			forAny, ctxWith("s3"), false},
		{"11: ForAnyValue / aud absent -> deny",
			forAny, ctxWith(), false},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := EvalConditionBlock(tc.block, tc.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %v got %v", tc.want, got)
			}
		})
	}
}

// TestEvalCondition_IpAddress exercises the IpAddress / NotIpAddress IAM
// condition operators including IPv4, IPv6, CIDR matching, missing-key
// semantics and malformed-pattern handling.
func TestEvalCondition_IpAddress(t *testing.T) {
	mk := func(vals ...string) map[string]*policy.ConditionValue {
		return map[string]*policy.ConditionValue{
			"aws:SourceIp": policy.NewConditionValueString(len(vals) == 1, vals...),
		}
	}

	tests := []struct {
		desc    string
		op      string
		stmt    map[string]*policy.ConditionValue
		ctx     map[string]*policy.ConditionValue
		want    bool
		wantErr bool
	}{
		{
			desc: "IpAddress IPv4 exact (bare addr promoted to /32)",
			op:   "IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "192.0.2.7")},
			ctx:  mk("192.0.2.7"),
			want: true,
		},
		{
			desc: "IpAddress IPv4 CIDR match",
			op:   "IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "192.0.2.0/24")},
			ctx:  mk("192.0.2.42"),
			want: true,
		},
		{
			desc: "IpAddress IPv4 outside CIDR",
			op:   "IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "192.0.2.0/24")},
			ctx:  mk("198.51.100.1"),
			want: false,
		},
		{
			desc: "IpAddress IPv6 CIDR match",
			op:   "IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "2001:db8::/32")},
			ctx:  mk("2001:db8:1::1"),
			want: true,
		},
		{
			desc: "IpAddress mixed v4 and v6 patterns - v4 hit",
			op:   "IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(false, "10.0.0.0/8", "2001:db8::/32")},
			ctx:  mk("10.1.2.3"),
			want: true,
		},
		{
			desc: "IpAddress mixed v4 and v6 patterns - v6 hit",
			op:   "IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(false, "10.0.0.0/8", "2001:db8::/32")},
			ctx:  mk("2001:db8:abcd::1"),
			want: true,
		},
		{
			desc: "NotIpAddress denies when inside CIDR",
			op:   "NotIpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "10.0.0.0/8")},
			ctx:  mk("10.5.6.7"),
			want: false,
		},
		{
			desc: "NotIpAddress allows when outside CIDR",
			op:   "NotIpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "10.0.0.0/8")},
			ctx:  mk("192.0.2.1"),
			want: true,
		},
		{
			desc: "IpAddress missing key is false",
			op:   "IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "10.0.0.0/8")},
			ctx:  map[string]*policy.ConditionValue{},
			want: false,
		},
		{
			desc: "NotIpAddress missing key is true",
			op:   "NotIpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "10.0.0.0/8")},
			ctx:  map[string]*policy.ConditionValue{},
			want: true,
		},
		{
			desc:    "IpAddress malformed pattern errors (fail closed)",
			op:      "IpAddress",
			stmt:    map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "not-an-ip")},
			ctx:     mk("10.0.0.1"),
			want:    false,
			wantErr: true,
		},
		{
			desc:    "IpAddress malformed CIDR errors",
			op:      "IpAddress",
			stmt:    map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "10.0.0.0/40")},
			ctx:     mk("10.0.0.1"),
			want:    false,
			wantErr: true,
		},
		{
			desc: "ForAnyValue:IpAddress with single context value still works",
			op:   "ForAnyValue:IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(true, "192.0.2.0/24")},
			ctx:  mk("192.0.2.5"),
			want: true,
		},
		{
			desc: "IpAddress malformed sibling pattern is ignored when valid pattern matches",
			op:   "IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(false, "not-an-ip", "10.0.0.0/8")},
			ctx:  mk("10.1.2.3"),
			want: true,
		},
		{
			desc:    "IpAddress malformed sibling pattern surfaces error when no pattern matches",
			op:      "IpAddress",
			stmt:    map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(false, "not-an-ip", "10.0.0.0/8")},
			ctx:     mk("192.0.2.1"),
			want:    false,
			wantErr: true,
		},
		{
			desc: "ForAnyValue:IpAddress matching value wins over erroring sibling pattern",
			op:   "ForAnyValue:IpAddress",
			stmt: map[string]*policy.ConditionValue{"aws:SourceIp": policy.NewConditionValueString(false, "not-an-ip", "10.0.0.0/8")},
			ctx:  mk("10.9.8.7"),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := evalCondition(tc.op, tc.stmt, tc.ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %v got %v", tc.want, got)
			}
		})
	}
}

// TestWithSourceIP ensures the helper only adds aws:SourceIp when a
// non-empty address is provided.
func TestWithSourceIP(t *testing.T) {
	base := IAMAction{Action: "s3:GetObject", Resource: "*"}

	got := WithSourceIP(base, "")
	if _, ok := got.Context["aws:SourceIp"]; ok {
		t.Fatalf("empty source IP must not populate aws:SourceIp")
	}

	got = WithSourceIP(base, "192.0.2.1")
	cv, ok := got.Context["aws:SourceIp"]
	if !ok {
		t.Fatalf("aws:SourceIp not set")
	}
	vals, _, _ := cv.Values()
	if len(vals) != 1 || vals[0] != "192.0.2.1" {
		t.Fatalf("unexpected aws:SourceIp values: %v", vals)
	}
}
