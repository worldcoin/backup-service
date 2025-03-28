#!/bin/bash
# Create S3 bucket for backup storage
awslocal s3 mb s3://backup-service-bucket
awslocal s3api put-bucket-versioning --bucket backup-service-bucket --versioning-configuration Status=Enabled

awslocal kms create-key --key-usage ENCRYPT_DECRYPT --region us-east-1 --key-spec SYMMETRIC_DEFAULT --tags '[{"TagKey":"_custom_id_","TagValue":"01926dd6-f510-7227-9b63-da8e18607615"}]'

# "wrong" key for tests
awslocal kms create-key --key-usage ENCRYPT_DECRYPT --region us-east-1 --key-spec SYMMETRIC_DEFAULT --tags '[{"TagKey":"_custom_id_","TagValue":"01926dd6-f510-7227-9b63-da8e18607614"}]'

echo "AWS LocalStack resources initialized successfully!"