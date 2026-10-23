"""Playbook automation: contain a public S3 bucket.

Usage:
  python3 remediate_public_s3.py <bucket>            # dry run: report only
  python3 remediate_public_s3.py <bucket> --apply    # turn on all four Block Public Access settings

Containment only. It deliberately leaves the bucket policy in place as evidence
for the investigation (Block Public Access makes it ineffective). Remove or fix
the policy, and fix the Terraform that created it, after the investigation.
"""
import sys

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")


def policy_is_public(bucket):
    try:
        return s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return False
        raise


def block_settings(bucket):
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise


def main():
    bucket = sys.argv[1]
    apply = "--apply" in sys.argv

    print(f"Bucket: {bucket}")
    print(f"  Policy is public:     {policy_is_public(bucket)}")
    print(f"  Block Public Access:  {block_settings(bucket) or 'not set'}")

    if not apply:
        print("Dry run: no changes made. Re-run with --apply to contain.")
        return

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print("Applied Block Public Access. Evidence after the change:")
    print(f"  Policy is public:     {policy_is_public(bucket)}")
    print(f"  Block Public Access:  {block_settings(bucket)}")


if __name__ == "__main__":
    main()
