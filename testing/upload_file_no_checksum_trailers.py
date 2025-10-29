import sys
import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config

bucket = sys.argv[1]
key = sys.argv[2]
file_path = sys.argv[3]
endpoint_url = sys.argv[4]
region_name = sys.argv[5]

mb = 1024**2
config = TransferConfig(multipart_threshold=50 * mb)

session = boto3.Session(region_name=region_name)
_s3 = session.client(
    "s3",
    endpoint_url=endpoint_url,
    config=Config(
        request_checksum_calculation="when_required",
        retries = {
            'total_max_attempts': 1,
            'mode': 'standard'
        }
    ),
    verify=False
)

_s3.upload_file(str(file_path), bucket, key, Config=config)
