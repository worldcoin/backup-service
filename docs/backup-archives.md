# Backup archive storage

Metadata selects an immutable ciphertext object at
`<backup-account-id>/backups/archive_<compact-uuid>`. Accounts without an `archiveId`
still read the legacy `<backup-account-id>/backup` object. Archive IDs are internal
and are omitted from the client metadata response.

Create uploads the ciphertext before conditionally creating metadata. Sync uploads
the replacement before conditionally publishing its archive ID and manifest hash.
An unconfirmed publication leaves its uploaded object in place because S3 may have
accepted the write even when the response was lost.

All account mutations and authenticated reads acquire the same Redis account lock.
Readers hold it until the complete ciphertext is in memory. Operations stop within
25 seconds; the lock expires after 120 seconds if the process dies. Redis must retain
lock keys until release or expiry; eviction or lost Redis writes invalidate mutual
exclusion. Conditional metadata writes remain the storage conflict check.

After a successful sync, the service deletes the previous archive, including the
legacy object. A cleanup failure is logged and counted without failing the committed
sync. Its deadline includes upload parsing and authentication, leaving time to send
the response before the server timeout.

Delete, reset, and removal of the last main factor capture the account's object keys
and factor lookup rows before unpublishing metadata. Metadata deletion checks its
ETag, and lookup deletion checks the captured owner and creation timestamp. Archive
deletion uses only captured keys, so a delayed request cannot list newly created
archives. Factor membership also supplies lookup keys because the DynamoDB account
index is eventually consistent.

S3 and DynamoDB do not share a transaction. A crash, failed delete, or uncertain write
can leave ciphertext or lookup rows behind. This change has no expiration markers,
background worker, or durable cleanup queue. A failed deletion returns an error;
once metadata is removed, the same authenticated request cannot finish the cleanup.

Deployment must drain old service instances before enabling this behavior: they do
not take the shared account lock. The service role needs `s3:ListBucket` in addition
to object read, write, and delete permissions. Physical deletion assumes an
unversioned bucket; retained S3 versions require a separate retention policy.

LocalStack 4.14 does not enforce ETags in `DeleteObjects`. Contract tests separately
check the conditional request and ensure a rejected deletion retains the archives.
