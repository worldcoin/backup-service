#!/bin/bash
# Create S3 bucket for backup storage (without SSE)
awslocal s3 mb s3://backup-service-bucket
awslocal s3api put-bucket-versioning --bucket backup-service-bucket --versioning-configuration Status=Enabled

# Create S3 bucket for SSE-C testing
awslocal s3 mb s3://backup-service-bucket-sse
awslocal s3api put-bucket-versioning --bucket backup-service-bucket-sse --versioning-configuration Status=Enabled
awslocal kms create-key --key-usage ENCRYPT_DECRYPT --region us-east-1 --key-spec SYMMETRIC_DEFAULT --tags '[{"TagKey":"_custom_id_","TagValue":"00000000-f510-7227-9b63-da8e18607616"}]'

# KMS Key for Challenge Token Encryption
awslocal kms create-key --key-usage ENCRYPT_DECRYPT --region us-east-1 --key-spec SYMMETRIC_DEFAULT --tags '[{"TagKey":"_custom_id_","TagValue":"01926dd6-f510-7227-9b63-da8e18607615"}]'

# "wrong" key for tests
awslocal kms create-key --key-usage ENCRYPT_DECRYPT --region us-east-1 --key-spec SYMMETRIC_DEFAULT --tags '[{"TagKey":"_custom_id_","TagValue":"01926dd6-f510-7227-9b63-da8e18607614"}]'


# dynamodb for factor lookup
awslocal dynamodb create-table \
    --table-name backup-service-factor-lookup \
    --key-schema AttributeName=PK,KeyType=HASH \
    --attribute-definitions \
        AttributeName=PK,AttributeType=S  \
        AttributeName=BackupId,AttributeType=S \
  --region us-east-1 \
  --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5 \
  --global-secondary-indexes \
      "[{\"IndexName\": \"GSI_BackupId\", \
                     \"KeySchema\":[{\"AttributeName\":\"BackupId\",\"KeyType\":\"HASH\"}], \
                     \"Projection\":{\"ProjectionType\":\"KEYS_ONLY\"}, \
                     \"ProvisionedThroughput\":{\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}}]"

echo "AWS LocalStack resources initialized successfully!"