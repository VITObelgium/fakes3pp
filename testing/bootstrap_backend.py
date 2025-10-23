import boto3
import os
import sys
from glob import glob
from pathlib import Path


# Set fake credentials to be used against moto
os.environ['AWS_ACCESS_KEY_ID'] = "moto-mocked"
os.environ['AWS_SECRET_ACCESS_KEY'] = "moto-mocked"

if len(sys.argv) != 3:
    raise RuntimeError("Expect invocation bootstrap_backend.py <local_backend_path> <endpoint_url>")
else:
    endpoint_url = sys.argv[2]
    local_backend_path = Path(sys.argv[1])
    print(f"Bootstrapping {endpoint_url} using {local_backend_path}")
    if not local_backend_path.is_dir():
        raise RuntimeError(f"Expect <local_backend_path> to be a directory got {local_backend_path}")
    region_name = local_backend_path.stem


def get_s3client():
    session = boto3.session.Session()

    return session.client(
        service_name='s3',
        endpoint_url=endpoint_url,
        region_name=region_name,
    )


def create_bucket(s3_client, bucket_name: str):
    try:
        return s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': region_name,
            },
        )
    except s3_client.exceptions.BucketAlreadyOwnedByYou:
        # For idempotency we do not fail if a bucket already exists
        return None


def copy_file_to_bucket(s3_client, source_file: Path, bucket_name:str, object_key: str):
    print(f"Moving {source_file} to s3://{bucket_name}/{object_key}")
    s3_client.upload_file(source_file, bucket_name, object_key)


def process_bucket(s3_client, bucket_dir: str):
    """
    Bootstrap a bucket based on a directory that looks like the bucket contents
    """
    bucket_path = Path(bucket_dir)
    bucket_name = bucket_path.stem
    print(f"Processing bucket {bucket_name} in {region_name}")
    create_bucket(s3_client, bucket_name)
    for file in glob(str(bucket_path.joinpath("*")), recursive=True):
        file_path = Path(file)
        if file_path.is_dir():
            continue  # We don´t mimic the directories in our object store
        if not file_path.is_file():
            raise RuntimeError(f"Unsupported filesystem object {file_path}")
        print(f"Processing file {file}")
        object_key = str(file).replace(f"{bucket_dir}/", "")
        copy_file_to_bucket(s3_client, file_path, bucket_name, object_key)


if __name__ == '__main__':
    s3_client = get_s3client()
    for bucket_dir in glob(str(local_backend_path.joinpath("*"))):
        process_bucket(s3_client, bucket_dir)
