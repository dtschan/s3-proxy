# s3-proxy
Reverse Proxy signing requests for S3 object store. Allows to up- and download files to/from S3 buckets with curl only.

## Installation on OpenShift

```sh
oc new-app https://github.com/puzzle/s3-proxy
```

Or if you prefer a DeploymentConfig instead of a Deployment

```sh
oc new-app  https://github.com/puzzle/s3-proxy --as-deployment-config
```

## Usage

```sh
curl -sS -H S3-Host:<S3 host> -H Access-Key:<bucket access-key> -H Secret-Key:<S3 bucket secret key> https://<s3-proxy host>/<S3 bucket path>
```
