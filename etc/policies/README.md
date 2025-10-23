# Policies

## Naming

The name of a policy is an AWS role ARN (e.g. `arn:aws:iam::000000000000:role/S3Access`). To not cause issues with filesystems this string is encoded using base32 where character '8' is used for padding.

So if you have an url you can easily get the filename for the role.

```sh
> echo -n "arn:aws:iam::000000000000:role/S3Access" | base32 | tr '=' '8'
MFZG4OTBO5ZTU2LBNU5DUMBQGAYDAMBQGAYDAMBQHJZG63DFF5JTGQLDMNSXG4Y8
```

Then just add the suffix `.json.tmpl`

## Syntax

Syntax is similar to AWS policies.

### Golang templating

There is support for Golang templating in order to add claims into the policy. At this time documentation on what
is supported are the test examples in cmd/policy_generation_test.go.
