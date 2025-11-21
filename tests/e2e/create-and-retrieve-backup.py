#!/usr/bin/env python3


"""
An end-to-end Python test script for the backup service.

1. **Generate EC keypairs** for main factor and sync factor
2. **Create backup** with main factor authentication and initial sync factor
3. **Retrieve metadata** using sync factor to get current manifest hash
4. **Sync backup** with updated content using sync factor
5. **Retrieve full backup** using main factor
"""

import argparse
import base64
import json
import os
import sys
from typing import Dict, Tuple, Any

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption


def generate_keypair() -> Tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate an EC keypair and return the private key and base64-encoded public key."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )
    public_base64 = base64.b64encode(public_bytes).decode('utf-8')
    return private_key, public_base64


def sign_challenge(private_key: ec.EllipticCurvePrivateKey, challenge_base64: str) -> str:
    """Sign a base64-encoded challenge with the private key and return the signature as base64."""
    challenge_bytes = base64.b64decode(challenge_base64)
    signature = private_key.sign(
        challenge_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    
    # Convert from raw signature to DER format
    r, s = decode_dss_signature(signature)
    der_signature = encode_dss_signature(r, s)
    
    return base64.b64encode(der_signature).decode('utf-8')


def create_backup(base_url: str, attestation_token: str = None) -> Tuple[Dict[str, Any], ec.EllipticCurvePrivateKey, ec.EllipticCurvePrivateKey]:
    """
    Create a backup with EC keypair authentication and a sync factor.

    Returns:
        Tuple of (response_data, main_private_key, sync_private_key)
    """
    print("Generating main EC keypair...")
    main_private_key, main_public_key = generate_keypair()

    # Generate backup_account_id from the main public key (compressed SEC1 format)
    main_public_key_obj = main_private_key.public_key()
    compressed_public_key = main_public_key_obj.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.CompressedPoint
    )
    backup_account_id = "backup_account_" + compressed_public_key.hex()
    print(f"Generated backup_account_id: {backup_account_id}")

    print("Generating sync factor EC keypair...")
    sync_private_key, sync_public_key = generate_keypair()

    # Get challenge for main keypair
    print("Requesting main challenge...")
    challenge_response = requests.post(f"{base_url}/v1/create/challenge/keypair", json={})
    print(f"Challenge status code: {challenge_response.status_code}")
    try:
        challenge_data = challenge_response.json()
        print(f"Challenge response: {challenge_data}")
    except Exception as e:
        print(f"Error parsing challenge response: {e}")
        print(f"Response text: {challenge_response.text}")
        raise
    
    main_challenge = challenge_data["challenge"]
    main_token = challenge_data["token"]
    
    # Sign challenge with main keypair
    main_signature = sign_challenge(main_private_key, main_challenge)
    print(f"Signed main challenge: {main_signature[:20]}...")
    
    # Get challenge for sync keypair
    print("Requesting sync factor challenge...")
    sync_challenge_response = requests.post(f"{base_url}/v1/create/challenge/keypair", json={})
    sync_challenge_data = sync_challenge_response.json()
    
    sync_challenge = sync_challenge_data["challenge"]
    sync_token = sync_challenge_data["token"]
    
    # Sign challenge with sync keypair
    sync_signature = sign_challenge(sync_private_key, sync_challenge)
    print(f"Signed sync challenge: {sync_signature[:20]}...")
    
    # Create backup
    print("Creating backup...")
    headers = {}
    if attestation_token:
        headers["attestation-token"] = attestation_token

    payload = {
        "authorization": {
            "kind": "EC_KEYPAIR",
            "publicKey": main_public_key,
            "signature": main_signature,
        },
        "challengeToken": main_token,
        "initialEncryptionKey": {
            "kind": "PRF",
            "encryptedKey": "MOCK_ENCRYPTED_KEY",
        },
        "initialSyncFactor": {
            "kind": "EC_KEYPAIR",
            "publicKey": sync_public_key,
            "signature": sync_signature,
        },
        "initialSyncChallengeToken": sync_token,
        "manifestHash": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "backupAccountId": backup_account_id,
    }
    
    # Create multipart form-data
    files = {
        'payload': ('payload.json', json.dumps(payload), 'application/json'),
        'backup': ('backup.bin', b'THIS IS A MOCK BACKUP', 'application/octet-stream')
    }
    
    create_response = requests.post(f"{base_url}/v1/create", files=files, headers=headers)

    if create_response.status_code != 200:
        print(f"Error creating backup: {create_response.status_code}")
        print(create_response.text)
        sys.exit(1)
    
    create_data = create_response.json()
    print(f"Backup created with ID: {create_data['backupId']}")
    
    return create_data, main_private_key, sync_private_key


def retrieve_backup(base_url: str, backup_id: str, private_key: ec.EllipticCurvePrivateKey, attestation_token: str = None) -> Dict[str, Any]:
    """Retrieve a backup using the main keypair."""
    print(f"Retrieving backup {backup_id}...")
    
    # Get challenge for keypair
    challenge_response = requests.post(f"{base_url}/v1/retrieve/challenge/keypair", json={})
    challenge_data = challenge_response.json()
    
    challenge = challenge_data["challenge"]
    token = challenge_data["token"]
    
    # Sign challenge with keypair
    signature = sign_challenge(private_key, challenge)
    
    # Derive public key from private key
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )
    public_base64 = base64.b64encode(public_bytes).decode('utf-8')
    
    # Retrieve backup
    retrieve_payload = {
        "authorization": {
            "kind": "EC_KEYPAIR",
            "publicKey": public_base64,
            "signature": signature,
        },
        "challengeToken": token,
    }
    
    # Add attestation token header if provided
    headers = {}
    if attestation_token:
        headers["attestation-token"] = attestation_token

    retrieve_response = requests.post(f"{base_url}/v1/retrieve/from-challenge", json=retrieve_payload, headers=headers)
    
    if retrieve_response.status_code != 200:
        print(f"Error retrieving backup: {retrieve_response.status_code}")
        print(retrieve_response.text)
        sys.exit(1)
    
    retrieve_data = retrieve_response.json()
    # Add debug output to see the actual response
    print(f"Retrieve response keys: {retrieve_data.keys()}")
    print(f"Retrieved backup with metadata")
    print(f"Backup content length: {len(retrieve_data.get('backup', ''))}")
    
    return retrieve_data


def retrieve_metadata(base_url: str, backup_id: str, sync_private_key: ec.EllipticCurvePrivateKey, attestation_token: str = None) -> Dict[str, Any]:
    """Retrieve backup metadata using the sync factor keypair."""
    print(f"Retrieving metadata for backup {backup_id}...")

    # Get challenge for keypair
    challenge_response = requests.post(f"{base_url}/v1/retrieve-metadata/challenge/keypair", json={})
    challenge_data = challenge_response.json()
    
    challenge = challenge_data["challenge"]
    token = challenge_data["token"]
    
    # Sign challenge with sync keypair
    signature = sign_challenge(sync_private_key, challenge)
    
    # Derive public key from private key
    public_key = sync_private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )
    public_base64 = base64.b64encode(public_bytes).decode('utf-8')
    
    # Retrieve metadata
    retrieve_payload = {
        "authorization": {
            "kind": "EC_KEYPAIR",
            "publicKey": public_base64,
            "signature": signature,
        },
        "challengeToken": token,
    }

    # Add attestation token header if provided
    headers = {}
    if attestation_token:
        headers["attestation-token"] = attestation_token

    retrieve_response = requests.post(f"{base_url}/v1/retrieve-metadata", json=retrieve_payload, headers=headers)

    if retrieve_response.status_code != 200:
        print(f"Error retrieving metadata: {retrieve_response.status_code}")
        print(retrieve_response.text)
        sys.exit(1)
    
    retrieve_data = retrieve_response.json()
    print(f"Retrieved metadata for backup with ID: {retrieve_data['id']}")

    # Pretty print the metadata structure
    print("\nBackup Metadata:")
    print(f"  ID: {retrieve_data['id']}")
    print(f"  Factors: {len(retrieve_data['factors'])}")
    print(f"  Sync Factors: {len(retrieve_data['syncFactors'])}")
    print(f"  Keys: {len(retrieve_data['keys'])}")
    
    return retrieve_data


def sync_backup(base_url: str, backup_id: str, sync_private_key: ec.EllipticCurvePrivateKey, new_content: bytes, attestation_token: str = None, current_manifest_hash: str = None, new_manifest_hash: str = None) -> Dict[str, Any]:
    """Sync (update) a backup using the sync factor keypair."""
    print(f"Syncing backup {backup_id}...")

    # Get challenge for sync keypair
    challenge_response = requests.post(f"{base_url}/v1/sync/challenge/keypair", json={})
    challenge_data = challenge_response.json()
    
    challenge = challenge_data["challenge"]
    token = challenge_data["token"]
    
    # Sign challenge with sync keypair
    signature = sign_challenge(sync_private_key, challenge)
    
    # Derive public key from private key
    public_key = sync_private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )
    public_base64 = base64.b64encode(public_bytes).decode('utf-8')
    
    # Sync backup
    payload = {
        "authorization": {
            "kind": "EC_KEYPAIR",
            "publicKey": public_base64,
            "signature": signature,
        },
        "challengeToken": token,
        "currentManifestHash": current_manifest_hash,
        "newManifestHash": new_manifest_hash,
    }
    
    # Create multipart form-data
    files = {
        'payload': ('payload.json', json.dumps(payload), 'application/json'),
        'backup': ('backup.bin', new_content, 'application/octet-stream')
    }

    # Add attestation token header if provided
    headers = {}
    if attestation_token:
        headers["attestation-token"] = attestation_token

    sync_response = requests.post(f"{base_url}/v1/sync", files=files, headers=headers)

    if sync_response.status_code != 200:
        print(f"Error syncing backup: {sync_response.status_code}")
        print(sync_response.text)
        sys.exit(1)
    
    sync_data = sync_response.json()
    print(f"Backup synced with ID: {sync_data['backupId']}")
    
    return sync_data


def main():
    parser = argparse.ArgumentParser(description='Create and retrieve a backup from the backup service')
    parser.add_argument('--url', default='http://localhost:3000', help='Base URL of the backup service')
    parser.add_argument('--attestation-token', help='Attestation token for protected endpoints')
    args = parser.parse_args()

    # Use environment variable if not provided as argument
    attestation_token = args.attestation_token or os.getenv('ATTESTATION_TOKEN')
    
    # Step 1: Create a backup
    create_data, main_private_key, sync_private_key = create_backup(args.url, attestation_token)
    backup_id = create_data["backupId"]

    # Step 2: Retrieve the backup metadata using sync factor
    metadata = retrieve_metadata(args.url, backup_id, sync_private_key, attestation_token)
    current_manifest_hash = metadata['manifestHash']

    # Step 3: Sync (update) the backup with new content
    new_content = b"THIS IS AN UPDATED MOCK BACKUP"
    new_manifest_hash = "aaadef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    sync_backup(args.url, backup_id, sync_private_key, new_content, attestation_token, current_manifest_hash, new_manifest_hash)

    # Step 4: Retrieve the backup using main factor
    retrieve_data = retrieve_backup(args.url, backup_id, main_private_key, attestation_token)
    
    print("\nBackup flow completed successfully!")
    print(f"Retrieved backup with keys: {list(retrieve_data.keys())}")
    print(f"Retrieved backup content: {base64.b64decode(retrieve_data['backup'])}")
    if 'metadata' in retrieve_data:
        print(f"Backup metadata ID: {retrieve_data['metadata']['id']}")


if __name__ == "__main__":
    main()
