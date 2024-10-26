"""
This file was used to generate test content for query_string_test.go
"""
from copy import deepcopy
import boto3


S3_ENDPOINT = "https://s3.test.com"

creds_with_temporary = {
    "aws_access_key_id": "0123455678910abcdef09459",
    "aws_secret_access_key": "YWUzOTQyM2FlMDMzNDlkNjk0M2FmZDE1OWE1ZGRkMT",
    "aws_session_token": "FQoGZXIvYXdzEBYaDkiOiJ7XG5cdFwiVmVyc2lvblwiOiBcIjIwMTItMTAtMTdcIixcblx0XCJT"
}
creds_long_term = deepcopy(creds_with_temporary)
creds_long_term.pop("aws_session_token")

test_bucket = "my-bucket"
test_key = "path/to/my_file"


def gen_presigned_url(creds) ->str:
    s = boto3.Session(
        **creds
    )
    c = s.client(
        "s3",
        endpoint_url=S3_ENDPOINT
    )
    return c.generate_presigned_url(
        'get_object',
        Params={'Bucket': test_bucket, 'Key': test_key},
        ExpiresIn=3600
    )


def get_expires_from_url(url: str) -> str:
    query_id = "&Expires="
    epoch_length = 10
    part_of_interest = url[-(len(query_id)+epoch_length):]
    assert part_of_interest.startswith(query_id)
    return part_of_interest[-epoch_length:]


url_from_perm = gen_presigned_url(creds_long_term)
url_from_temp = gen_presigned_url(creds_with_temporary)

assert get_expires_from_url(url_from_temp) == get_expires_from_url(url_from_perm), "Race hit just run again"

print(f"""
var testUrl = "{S3_ENDPOINT}/{test_bucket}/{test_key}" 
var testAccessKeyId = "{creds_with_temporary['aws_access_key_id']}"
var testSecretAccessKey = "{creds_with_temporary['aws_secret_access_key']}"
var testSessionToken = "{creds_with_temporary['aws_session_token']}"
var testExpires = "{get_expires_from_url(url_from_temp)}"
var testExpectedPresignedUrlTemp = "{url_from_temp}"
var testExpectedPresignedUrlPerm = "{url_from_perm}"
""")