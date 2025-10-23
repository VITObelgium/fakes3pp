# fakes3++

The goal of fake S3 plus plus is to enrich S3 compatible API's to close the gap with
(Amazon's S3 service)[https://aws.amazon.com/pm/serv-s3] which is feature rich compared to alternate implementations.

## Scope

### Goals
  - Support OIDC authentication
  - Support presigned URLs
  - Support authorization for fine-grained access rules based on OIDC subject
  - Maximise compatibility with original AWS (S3) clients

### Non-Goals
  - Store Data (a Downstream service is used with an S3 compatible API)


### API overview

This section details the actions that can be handled by the proxy

#### S3
- ListObjectsV2
- GetObject
- ListBuckets
- HeadBucket
- HeadObject
- PutObject
- CreateMultipartUpload
- CompleteMultipartUpload
- AbortMultipartUpload
- UploadPart

#### STS
 - AssumeRoleWithWebIdentity


## Running

### Building the container image

Both the S3 and STS proxy are served by the same container image which can be built using `make build-container`

## Configuration

See cmd/config.go to see all the configuration parameters and their description. Configuration is set using environment variables.

### Minimal configuration
To get started quickly there is an example config file under etc/.env.docker.

Create your private configuration copy:
```sh
cp -R etc etc.private
```

Next adapt the config under etc.private. To get a minimal working local proxy you need to change at least:
 - etc.private/backend-config.yaml
   - The example shows config for 2 S3 backends. Remove and add config as per your use case.
   - The additional files you can create under etc.private as they get mounted under /etc/fakes3pp

### Production configuration

For a production configuration you MUST stay away from default certificates and keypairs.
Read `etc/README.md` on how to generate your own secrets and update your .env.docker to point to those.

Also add more restricting policies under `etc/policies` to match your use cases.

### Run the proxy locally using podman

After creating your private env config files the proxies can be started with the following `make` commands:
 - stsproxy: `make run-container-sts`
 - s3proxy:  `make run-container-s3`

## Using the proxy

1. Get an access token from your OIDC provider
2. Perform an AssumeRoleWithWebIdentity call against the sts proxy (e.g. localhost:8444) to get temporary credentials
  - RoleArn: the arn of a supported policy (e.g. `arn:aws:iam::000000000000:role/S3Access`)
  - RoleSessionName: can be freely chosen
  - WebIdentityToken: (The token from step 1)
3A. Perform a supported (see API overview) AWS S3 API call against the s3 proxy (e.g. localhost:8443)
  - Specify the credentials from 2
  - Use a bucket that is available in the object store that is being proxied
3B. Create a Pre-signed url using the credentials from 2 (e.g. see cmd/s3-presigner_test.py)


## Why?

At the time we needed this functionality we couldn't find a product that met our needs. Every product we encountered had a mismatch intrinsic to the design. We mention the following two because if they fit your use case then trying to use fakes3pp probably does not make sense.

### Mismatch UC1: I want to manage my own storage

There is (MinIO)[https://github.com/minio] which would have met our requirements but it runs against local storage rather than against other Object stores. So if you are not targetting Object storage their product might be a good fit as they also offer:
   - OIDC integration for authn/authz
   - presigned URLs

Their work was quite a source of inspiration so we decided to base some work on them and therefore publish our code under GNU AFFERO GENERAL PUBLIC LICENSE.


### Mismatch UC2: I want a custom REST API

Products that run against S3 object stores often provide an API that is not S3 compatible towards clients (e.g. https://github.com/oxyno-zeta/s3-proxy). It also offers a way of OIDC integration but the frontend interface is not S3 API compatible.


## Contributing

Contributions are welcome. When contributing something not on our radar it is recommended to open an issue before investing in development to see if the contribution sounds like a good fit. It could also help to exchange ideas on the preferred way to add it.

### Running tests

The CICD workflow is visible in the repository and is most likely the best guide to running all the tests. Some points of attention:

#### Slow tests
There are slow unittests disabled by default. If you want to run them locally set an enviornment variable `HASTE_MAKES_WASTE` and give it any value (e.g. `export HASTE_MAKES_WASTE=true`)

When adding a test yourself that is slow make sure to use `testutils.SkipIfNoSlowUnittests(t)` to avoid running it always

#### Tests against a test S3 implementation
Some tests run against an S3 implementation for testing (moto) see [testing/README.md](testing docs) for details.

These are located in [cmd/almost-e2e_test.go](cmd/almost-e2e_test.go)
