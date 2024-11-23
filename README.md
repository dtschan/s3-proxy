# s3-proxy
Reverse Proxy signing requests for S3 object store. Allows to up- and download files to/from S3 buckets with curl only. Optionally compresses the file while uploading it to S3.

## Installation on OpenShift

```sh
oc new-app https://github.com/puzzle/s3-proxy
```

Or if you prefer a DeploymentConfig instead of a Deployment

```sh
oc new-app  https://github.com/puzzle/s3-proxy --as-deployment-config
```

## Prerequisites

Only the `curl` tool is needed to use this proxy.

## Usage

```sh
curl -sS -H S3-Host:<S3 host> -H Access-Key:<bucket access-key> -H Secret-Key:<S3 bucket secret key> -H Compress-File:<compression method> https://<s3-proxy host>/<S3 bucket path>
```

Currently the only supported compression method is `gzip`. No compression is applied if no `Compress-File` header is set.

## Example

Upload Java Heap Dumps to S3, especially useful in Kubernetes Pods:

```sh
JAVA_TOOL_OPTIONS:
  -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/dump.hprof
  -XX:OnOutOfMemoryError="curl -T /tmp/dump.hprof
    -H S3-Host:s3-objects.example.org
    -H Access-Key:${S3_ACCESS_KEY}
    -H Secret-Key:${S3_SECRET_KEY}
    -H Compress-File:gzip
    https://s3-proxy.example.org/java-dumps/dump_$(cat /run/secrets/kubernetes.io/serviceaccount/namespace)_${HOSTNAME}.hprof.gz"
```           
