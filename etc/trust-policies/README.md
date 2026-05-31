# Trust policies

Trust policies control **whether a role can be assumed** via
`AssumeRoleWithWebIdentity`. They are the trust-time counterpart to the
permission policies under `etc/policies/`, which control what the role is
allowed to do once assumed.

The directory is exposed to the STS proxy via the environment variable
`FAKES3PP_ROLE_TRUST_POLICY_PATH`. It is intentionally separate from
`FAKES3PP_ROLE_POLICY_PATH` so that the two kinds of policy can be provisioned
through independent mechanisms (e.g. different config-maps, different
operators).

## Default-allow semantics

- If `FAKES3PP_ROLE_TRUST_POLICY_PATH` is not set, no trust policy evaluation
  is performed and any valid OIDC token may assume any defined role.
- If the variable is set but there is **no file** for a given role, that role
  is still allowed to be assumed (default-allow per role).
- If a file is present it is parsed and evaluated; the call only succeeds when
  the policy evaluates to `Allow` and no `Deny` matches.

## Naming

Identical to permission policies: `<base32(role ARN with '=' replaced by
'8')>.json.tmpl`. See `etc/policies/README.md` for the conversion command.

## Hot reload

Trust policy files are watched with the same `fsnotify`-based mechanism as the
permission policies. Edits, creations and deletions take effect on the next
`AssumeRoleWithWebIdentity` call for the affected role.

## Templating

The same Go `text/template` engine is used. The data made available to the
template is `iam.TrustPolicySessionData`:

```
.RoleArn                  string
.RoleSessionName          string
.DurationSeconds          int
.RequestedRegion          string
.Tags.PrincipalTags       map[string][]string
.Tags.TransitiveTagKeys   []string
.Claims.Subject           string
.Claims.Issuer            string
.Claims.Audience          []string
```

## Policy shape

Trust policies follow the standard AWS IAM trust-policy JSON shape:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "https://localhost/auth/realms/testing" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringLike":   { "localhost:sub": "test-*" },
        "StringEquals": { "aws:PrincipalTag/custom_id": "idA" }
      }
    }
  ]
}
```

### Principal

- `"Principal": "*"` and `{ "AWS": "*" }` are wildcards: every principal
  matches.
- `{ "Federated": "<oidc-issuer>" }` matches when the issuer URL of the
  presented OIDC token equals the value (or matches it as an IAM `StringLike`
  pattern with `*`/`?`).
- Other principal kinds (`AWS` with a non-wildcard value, `CanonicalUser`,
  `Service`) are currently not matched against a federated principal.
- A statement without a `Principal` is unconstrained — equivalent to
  permission-policy semantics.

### Action

Only `sts:AssumeRoleWithWebIdentity` is recognised. Use `*` to match it.

### Resource

The role ARN being assumed. `*` matches any role; otherwise IAM
`StringLike` rules (`*`/`?`) apply.

### Condition

The same operators supported elsewhere in the project are available:
`StringEquals`, `StringNotEquals`, `StringLike`, `StringNotLike`,
`IpAddress`, `NotIpAddress`, plus `Null` for presence checks. Numeric
and date operators are not implemented.

`IpAddress` / `NotIpAddress` accept either bare addresses (treated as
`/32` for IPv4 and `/128` for IPv6) or CIDR prefixes. Both IPv4 and IPv6
patterns are accepted by the same operator. An invalid pattern fails the
entire evaluation (deny) and is logged at info level so operators can
notice the misconfiguration.

Each operator may be prefixed with one of the AWS quantifiers
`ForAnyValue:` or `ForAllValues:` to evaluate multi-valued context keys
(see `<issuer-host>:aud` below):

- `ForAnyValue:<op>` — true when *at least one* value in the context key
  satisfies the per-value predicate. Missing key → false.
- `ForAllValues:<op>` — true when *every* value in the context key
  satisfies the per-value predicate. **Missing key → vacuously true.**
  When you also want to require the key to be present, combine with
  `Null:<key>: "false"`.

Unqualified operators against a multi-valued context key produce an
evaluation error (the request is denied) — policies must opt into
multi-valued evaluation explicitly via one of the quantifiers above.

The `Null` operator takes the literal values `"true"` or `"false"` and
does **not** accept a quantifier:

```json
"Condition": {
  "Null": { "localhost:aud": "false" }
}
```

Context keys exposed at trust evaluation time:

| Key                                  | Source                                              |
| ------------------------------------ | --------------------------------------------------- |
| `<issuer-host>:sub`                  | OIDC token `sub` claim                              |
| `<issuer-host>:iss`                  | OIDC token `iss` claim (full URL)                   |
| `<issuer-host>:aud`                  | OIDC token `aud` claim (multi-valued)               |
| `aws:PrincipalTag/<tag-key>`         | session tags carried by the token                   |
| `aws:RequestedRegion`                | populated when the requested region is known        |
| `aws:SourceIp`                       | apparent client IP (see "Source IP" below)          |
| `sts:RoleSessionName`                | from the AssumeRoleWithWebIdentity request          |
| `sts:DurationSeconds`                | requested credential lifetime (string comparison)   |

`<issuer-host>` is the host part of the issuer URL, lowercased. For an issuer
of `https://accounts.google.com/`, keys are `accounts.google.com:sub` etc. If
the issuer is not a parseable URL with a host the full issuer string is used
as the prefix.

#### Example: require a specific audience among many

```json
"Condition": {
  "ForAnyValue:StringEquals": { "localhost:aud": "fakes3pp" }
}
```

#### Example: lock the token down to a known set of audiences

```json
"Condition": {
  "ForAllValues:StringEquals": { "localhost:aud": ["fakes3pp", "internal"] },
  "Null":                       { "localhost:aud": "false" }
}
```

The `Null:false` clause prevents a token without any `aud` claim from
passing through the vacuously-true `ForAllValues` check.

#### Source IP

`aws:SourceIp` is populated from the apparent client IP address of the
incoming HTTP request. Resolution order:

1. First non-empty entry of the `X-Forwarded-For` request header
   (comma-separated, the left-most entry is the client).
2. `X-Real-IP` request header.
3. The host portion of the TCP `RemoteAddr` (port stripped).

This means the proxy can sit behind a load balancer that injects
`X-Forwarded-For`; ensure your fronting infrastructure strips any
client-supplied header to prevent spoofing.

Example: only allow assuming the role from an internal network:

```json
"Condition": {
  "IpAddress": { "aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"] }
}
```
