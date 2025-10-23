# etc

Here we keep sample configuration as used for unittests as wel as generated secrets for the unittests.

(!) These should NEVER be used except for unittests.

Security is driven by secrets being secret. If you want to deploy your own proxy generate your own Secrets!


## Generate your own secrets

### Generate self-signed certificates for spawning a local https listener

(i) If you want to host the proxy publicly consider getting a certificate signed by a trusted party (e.g. letsencrypt) instead of a self-signed certificate.

Example command; change subject as per your needs.
```
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509     \
    -subj "/C=BE/ST=Antwerp/L=Antwerp/O=Allinthemiddle/OU=Home/CN=localhost" \
    -keyout key.pem  -out cert.pem
```

### Generate RSA keypair for jwt

(i) This keypair is OK to generate yourself as it is a shared secret between the STS and S3 proxy and only they need to know of each other.

Easiest on Linux is to use `ssh-keygen`. For example we created a key for JWT testing:

```sh
ssh-keygen -t rsa -b 2048 -m PEM -f jwt_testing_rsa
ssh-keygen -f jwt_testing_rsa -e -m PEM > jwt_testing_rsa.pub
```

You should NOT use the files that ship in etc in real deployments. We use them for testing
as we hard code the public key part. Since we put the public and private part in this public
Github repository the key is compromised and therefore anyone could make valid JWT signatures
if you were to use these keys for a deployment.
