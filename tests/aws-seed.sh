#!/bin/bash
# Create S3 bucket for backup storage
awslocal s3 mb s3://backup-service-bucket
awslocal s3api put-bucket-versioning --bucket backup-service-bucket --versioning-configuration Status=Enabled

echo "AWS LocalStack resources initialized successfully!"