//! Binds the existing factor's add-factor authorization to the material of the factor actually
//! being added.
//!
//! The existing factor signs `existing_challenge || SHA256(TAG || encode(material))` instead of
//! the bare challenge, so a relay that can rewrite the request cannot swap the new credential — or
//! any other persisted request field — after the user approved the operation. The encoding in
//! this module is the wire contract shared with clients: the kind tag comes first, every
//! variable-length field is length-prefixed and every optional field carries a presence byte, so
//! no two distinct inputs share an encoding.

use sha2::{Digest, Sha256};
use types::BackupEncryptionKey;
use webauthn_rs::prelude::{COSEAlgorithm, COSEKey, COSEKeyType, ECDSACurve};

/// Domain-separation prefix hashed in front of the encoded material.
pub const ADD_FACTOR_BINDING_TAG: &[u8] = b"backup-service:add-factor-binding:v1";

/// Length of the challenge minted by `/add-factor/challenge` for the existing factor.
pub const EXISTING_FACTOR_CHALLENGE_LEN: usize = 32;

/// Length of the payload the existing factor signs: the challenge followed by the 32-byte
/// material digest. Every other payload the same session keypair signs is a bare 32-byte
/// challenge, so this fixed length is what keeps the two from ever being confused.
pub const EXISTING_FACTOR_SIGNED_PAYLOAD_LEN: usize = EXISTING_FACTOR_CHALLENGE_LEN + 32;

const KIND_TAG_PASSKEY: u8 = 0x01;
const KIND_TAG_OIDC: u8 = 0x02;
const FIELD_ABSENT: u8 = 0x00;
const FIELD_PRESENT: u8 = 0x01;
const ENCRYPTION_KEY_VARIANT_PRF: u8 = 0x01;
const ENCRYPTION_KEY_VARIANT_ICLOUD: u8 = 0x02;
const ENCRYPTION_KEY_VARIANT_TURNKEY: u8 = 0x03;

/// Hex-encoded SHA-256 of the `WebAuthn` registration state stored in the new-factor challenge
/// token. Binding this into the existing-factor token (see
/// [`NewFactorType::PasskeyRegistration`](crate::challenge_manager::NewFactorType::PasskeyRegistration))
/// prevents swapping a different registration ceremony after the old factor has signed.
#[must_use]
pub fn registration_state_hash(registration_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(registration_bytes))
}

/// The kind-specific part of the new-factor material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewFactorMaterialKind<'a> {
    /// A freshly registered passkey.
    ///
    /// The registration response bytes are bound verbatim on top of the credential id and key:
    /// with `none` attestation nothing else signs `authenticatorData`, so its sign count, flags and
    /// AAGUID — all persisted with the credential — could otherwise be rewritten in transit
    /// without changing the id or the key.
    Passkey {
        /// Raw credential id bytes (not base64).
        credential_id: &'a [u8],
        /// SEC1 uncompressed point, `0x04 || x || y`. See [`passkey_public_key_sec1`].
        public_key_sec1: &'a [u8; 65],
        /// The client-chosen label, exactly as submitted (empty when omitted).
        label: &'a str,
        /// `response.clientDataJSON`, the exact bytes the authenticator saw.
        client_data_json: &'a [u8],
        /// `response.attestationObject`, the exact bytes the authenticator produced.
        attestation_object: &'a [u8],
    },
    /// An OIDC account, identified by the compact JWT exactly as submitted.
    Oidc {
        /// The raw ID token.
        raw_jwt: &'a str,
    },
}

/// Everything the existing factor's signature commits to about the factor being added: the
/// credential or token itself plus the other request fields that get persisted alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewFactorMaterial<'a> {
    /// The credential or token.
    pub kind: NewFactorMaterialKind<'a>,
    /// `AddFactorRequest::turnkey_provider_id`, exactly as submitted (`None` when omitted).
    pub turnkey_provider_id: Option<&'a str>,
    /// `AddFactorRequest::encrypted_backup_key`, exactly as submitted.
    pub encrypted_backup_key: Option<&'a BackupEncryptionKey>,
}

impl NewFactorMaterial<'_> {
    /// The canonical byte encoding; clients must produce these exact bytes.
    ///
    /// # Panics
    /// If a field is longer than `u32::MAX` bytes. Request bodies are size-limited far below
    /// that, so this cannot happen for material built from an accepted request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self.kind {
            NewFactorMaterialKind::Passkey {
                credential_id,
                public_key_sec1,
                label,
                client_data_json,
                attestation_object,
            } => {
                out.push(KIND_TAG_PASSKEY);
                push_length_prefixed(&mut out, credential_id);
                push_length_prefixed(&mut out, public_key_sec1);
                push_length_prefixed(&mut out, label.as_bytes());
                push_length_prefixed(&mut out, client_data_json);
                push_length_prefixed(&mut out, attestation_object);
            }
            NewFactorMaterialKind::Oidc { raw_jwt } => {
                out.push(KIND_TAG_OIDC);
                push_length_prefixed(&mut out, raw_jwt.as_bytes());
            }
        }

        match self.turnkey_provider_id {
            None => out.push(FIELD_ABSENT),
            Some(turnkey_provider_id) => {
                out.push(FIELD_PRESENT);
                push_length_prefixed(&mut out, turnkey_provider_id.as_bytes());
            }
        }

        match self.encrypted_backup_key {
            None => out.push(FIELD_ABSENT),
            Some(BackupEncryptionKey::Prf { encrypted_key }) => {
                out.push(FIELD_PRESENT);
                out.push(ENCRYPTION_KEY_VARIANT_PRF);
                push_length_prefixed(&mut out, encrypted_key.as_bytes());
            }
            Some(BackupEncryptionKey::Icloud { encrypted_key }) => {
                out.push(FIELD_PRESENT);
                out.push(ENCRYPTION_KEY_VARIANT_ICLOUD);
                push_length_prefixed(&mut out, encrypted_key.as_bytes());
            }
            Some(BackupEncryptionKey::Turnkey {
                encrypted_key,
                turnkey_account_id,
                turnkey_user_id,
                turnkey_private_key_id,
            }) => {
                out.push(FIELD_PRESENT);
                out.push(ENCRYPTION_KEY_VARIANT_TURNKEY);
                push_length_prefixed(&mut out, encrypted_key.as_bytes());
                push_length_prefixed(&mut out, turnkey_account_id.as_bytes());
                push_length_prefixed(&mut out, turnkey_user_id.as_bytes());
                push_length_prefixed(&mut out, turnkey_private_key_id.as_bytes());
            }
        }

        out
    }

    /// `SHA256(TAG || encode())`, the 32 bytes appended to the existing-factor challenge.
    ///
    /// # Panics
    /// See [`Self::encode`].
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ADD_FACTOR_BINDING_TAG);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}

/// The bytes the existing factor signs — or, for a passkey, carries in the Turnkey activity's
/// `metadata.challenge` (standard base64) — to authorize adding the factor described by
/// `material_digest`.
#[must_use]
pub fn existing_factor_signed_payload(
    existing_challenge: &[u8; EXISTING_FACTOR_CHALLENGE_LEN],
    material_digest: &[u8; 32],
) -> [u8; EXISTING_FACTOR_SIGNED_PAYLOAD_LEN] {
    let mut payload = [0u8; EXISTING_FACTOR_SIGNED_PAYLOAD_LEN];
    payload[..EXISTING_FACTOR_CHALLENGE_LEN].copy_from_slice(existing_challenge);
    payload[EXISTING_FACTOR_CHALLENGE_LEN..].copy_from_slice(material_digest);
    payload
}

/// The SEC1 uncompressed encoding (`0x04 || x || y`) of an ES256 / P-256 passkey public key, the
/// only key type the binding is defined for. `None` for any other algorithm or coordinate shape;
/// add-factor rejects such registrations rather than guessing an encoding.
#[must_use]
pub fn passkey_public_key_sec1(public_key: &COSEKey) -> Option<[u8; 65]> {
    if public_key.type_ != COSEAlgorithm::ES256 {
        return None;
    }
    let COSEKeyType::EC_EC2(ec2_key) = &public_key.key else {
        return None;
    };
    // `alg: ES256` is only meaningful on P-256; a key that claims ES256 over another 32-byte
    // curve would otherwise produce a point clients cannot reproduce.
    if ec2_key.curve != ECDSACurve::SECP256R1 {
        return None;
    }
    let (x, y) = (ec2_key.x.as_slice(), ec2_key.y.as_slice());
    if x.len() != 32 || y.len() != 32 {
        return None;
    }

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..].copy_from_slice(y);
    Some(sec1)
}

fn push_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len())
        .expect("request field longer than u32::MAX bytes; bodies are size-limited far below this");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use webauthn_rs::prelude::{COSEEC2Key, ECDSACurve};

    const CRED_ID: &[u8] = &[0xAA, 0xBB, 0xCC];
    const CLIENT_DATA: &[u8] = br#"{"type":"webauthn.create"}"#;
    const ATTESTATION: &[u8] = &[0xA3, 0x63, 0x66, 0x6D, 0x74];

    fn sec1_key(fill: u8) -> [u8; 65] {
        let mut key = [fill; 65];
        key[0] = 0x04;
        key
    }

    fn lp(bytes: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn passkey_kind<'a>(
        credential_id: &'a [u8],
        public_key_sec1: &'a [u8; 65],
        label: &'a str,
        client_data_json: &'a [u8],
        attestation_object: &'a [u8],
    ) -> NewFactorMaterialKind<'a> {
        NewFactorMaterialKind::Passkey {
            credential_id,
            public_key_sec1,
            label,
            client_data_json,
            attestation_object,
        }
    }

    #[test]
    fn passkey_encoding_is_tagged_and_length_prefixed() {
        let sec1 = sec1_key(0x11);
        let material = NewFactorMaterial {
            kind: passkey_kind(CRED_ID, &sec1, "phone", CLIENT_DATA, ATTESTATION),
            turnkey_provider_id: Some("tp"),
            encrypted_backup_key: None,
        };

        let mut expected = vec![KIND_TAG_PASSKEY];
        expected.extend(lp(CRED_ID));
        expected.extend(lp(&sec1));
        expected.extend(lp(b"phone"));
        expected.extend(lp(CLIENT_DATA));
        expected.extend(lp(ATTESTATION));
        expected.push(FIELD_PRESENT);
        expected.extend(lp(b"tp"));
        expected.push(FIELD_ABSENT);
        assert_eq!(material.encode(), expected);
    }

    #[test]
    fn oidc_encoding_with_turnkey_key_lists_every_key_field_in_declared_order() {
        let key = BackupEncryptionKey::Turnkey {
            encrypted_key: "ek".to_string(),
            turnkey_account_id: "acct".to_string(),
            turnkey_user_id: "user".to_string(),
            turnkey_private_key_id: "pk".to_string(),
        };
        let material = NewFactorMaterial {
            kind: NewFactorMaterialKind::Oidc { raw_jwt: "a.b.c" },
            turnkey_provider_id: None,
            encrypted_backup_key: Some(&key),
        };

        let mut expected = vec![KIND_TAG_OIDC];
        expected.extend(lp(b"a.b.c"));
        expected.push(FIELD_ABSENT);
        expected.extend([FIELD_PRESENT, ENCRYPTION_KEY_VARIANT_TURNKEY]);
        expected.extend(lp(b"ek"));
        expected.extend(lp(b"acct"));
        expected.extend(lp(b"user"));
        expected.extend(lp(b"pk"));
        assert_eq!(material.encode(), expected);
    }

    #[test]
    fn absent_and_empty_turnkey_provider_id_encode_differently() {
        let material = |turnkey_provider_id| NewFactorMaterial {
            kind: NewFactorMaterialKind::Oidc { raw_jwt: "a.b.c" },
            turnkey_provider_id,
            encrypted_backup_key: None,
        };

        let absent = material(None).encode();
        let empty = material(Some("")).encode();
        assert_ne!(absent, empty);
        let tail_at = 1 + lp(b"a.b.c").len();
        assert_eq!(absent[tail_at], FIELD_ABSENT);
        assert_eq!(empty[tail_at], FIELD_PRESENT);
        assert_eq!(&empty[tail_at + 1..tail_at + 5], &0u32.to_be_bytes());
    }

    #[test]
    fn prf_and_icloud_keys_differ_only_by_the_variant_byte() {
        let prf = BackupEncryptionKey::Prf {
            encrypted_key: "ek".to_string(),
        };
        let icloud = BackupEncryptionKey::Icloud {
            encrypted_key: "ek".to_string(),
        };
        let material = |key| NewFactorMaterial {
            kind: NewFactorMaterialKind::Oidc { raw_jwt: "a.b.c" },
            turnkey_provider_id: None,
            encrypted_backup_key: Some(key),
        };

        let prf_bytes = material(&prf).encode();
        let icloud_bytes = material(&icloud).encode();
        let variant_at = 1 + lp(b"a.b.c").len() + 1 + 1;
        assert_eq!(prf_bytes[variant_at], ENCRYPTION_KEY_VARIANT_PRF);
        assert_eq!(icloud_bytes[variant_at], ENCRYPTION_KEY_VARIANT_ICLOUD);
        assert_eq!(prf_bytes[..variant_at], icloud_bytes[..variant_at]);
        assert_eq!(prf_bytes[variant_at + 1..], icloud_bytes[variant_at + 1..]);
    }

    #[test]
    fn digest_commits_to_every_field() {
        let sec1_a = sec1_key(0x11);
        let sec1_b = sec1_key(0x22);
        let key = BackupEncryptionKey::Prf {
            encrypted_key: "ek".to_string(),
        };
        let other_key = BackupEncryptionKey::Prf {
            encrypted_key: "ek2".to_string(),
        };
        let base = NewFactorMaterial {
            kind: passkey_kind(CRED_ID, &sec1_a, "phone", CLIENT_DATA, ATTESTATION),
            turnkey_provider_id: Some("tp"),
            encrypted_backup_key: Some(&key),
        };

        let variants = [
            base,
            NewFactorMaterial {
                kind: passkey_kind(
                    &[0xAA, 0xBB, 0xCD],
                    &sec1_a,
                    "phone",
                    CLIENT_DATA,
                    ATTESTATION,
                ),
                ..base
            },
            NewFactorMaterial {
                kind: passkey_kind(CRED_ID, &sec1_b, "phone", CLIENT_DATA, ATTESTATION),
                ..base
            },
            NewFactorMaterial {
                kind: passkey_kind(CRED_ID, &sec1_a, "laptop", CLIENT_DATA, ATTESTATION),
                ..base
            },
            NewFactorMaterial {
                kind: passkey_kind(CRED_ID, &sec1_a, "phone", b"{}", ATTESTATION),
                ..base
            },
            NewFactorMaterial {
                kind: passkey_kind(
                    CRED_ID,
                    &sec1_a,
                    "phone",
                    CLIENT_DATA,
                    &[0xA3, 0x63, 0x66, 0x6D, 0x75],
                ),
                ..base
            },
            NewFactorMaterial {
                turnkey_provider_id: Some("tp2"),
                ..base
            },
            NewFactorMaterial {
                turnkey_provider_id: Some(""),
                ..base
            },
            NewFactorMaterial {
                turnkey_provider_id: None,
                ..base
            },
            NewFactorMaterial {
                encrypted_backup_key: Some(&other_key),
                ..base
            },
            NewFactorMaterial {
                encrypted_backup_key: None,
                ..base
            },
            NewFactorMaterial {
                kind: NewFactorMaterialKind::Oidc { raw_jwt: "a.b.c" },
                ..base
            },
        ];

        let digests: HashSet<[u8; 32]> = variants.iter().map(NewFactorMaterial::digest).collect();
        assert_eq!(
            digests.len(),
            variants.len(),
            "every field must change the digest"
        );
    }

    #[test]
    fn digest_is_domain_separated_from_a_plain_hash_of_the_encoding() {
        let sec1 = sec1_key(0x11);
        let material = NewFactorMaterial {
            kind: passkey_kind(CRED_ID, &sec1, "", CLIENT_DATA, ATTESTATION),
            turnkey_provider_id: None,
            encrypted_backup_key: None,
        };

        let plain: [u8; 32] = Sha256::digest(material.encode()).into();
        assert_ne!(material.digest(), plain);

        let mut tagged = Sha256::new();
        tagged.update(ADD_FACTOR_BINDING_TAG);
        tagged.update(material.encode());
        let tagged: [u8; 32] = tagged.finalize().into();
        assert_eq!(material.digest(), tagged);
    }

    #[test]
    fn signed_payload_is_challenge_then_digest() {
        let challenge = [7u8; EXISTING_FACTOR_CHALLENGE_LEN];
        let digest = [9u8; 32];

        let payload = existing_factor_signed_payload(&challenge, &digest);

        assert_eq!(payload.len(), EXISTING_FACTOR_SIGNED_PAYLOAD_LEN);
        assert_eq!(payload[..32], challenge);
        assert_eq!(payload[32..], digest);
    }

    #[test]
    fn sec1_is_only_defined_for_es256_p256_keys() {
        let x = [1u8; 32];
        let y = [2u8; 32];
        let ec_key = |alg, curve, x: Vec<u8>, y: Vec<u8>| COSEKey {
            type_: alg,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve,
                x: x.into(),
                y: y.into(),
            }),
        };

        let sec1 = passkey_public_key_sec1(&ec_key(
            COSEAlgorithm::ES256,
            ECDSACurve::SECP256R1,
            x.to_vec(),
            y.to_vec(),
        ))
        .expect("ES256 P-256 key");
        assert_eq!(sec1[0], 0x04);
        assert_eq!(sec1[1..33], x);
        assert_eq!(sec1[33..], y);

        assert!(passkey_public_key_sec1(&ec_key(
            COSEAlgorithm::RS256,
            ECDSACurve::SECP256R1,
            x.to_vec(),
            y.to_vec()
        ))
        .is_none());
        // `alg: ES256` on a different curve must not be mistaken for a P-256 point.
        assert!(passkey_public_key_sec1(&ec_key(
            COSEAlgorithm::ES256,
            ECDSACurve::SECP384R1,
            x.to_vec(),
            y.to_vec()
        ))
        .is_none());
        assert!(passkey_public_key_sec1(&ec_key(
            COSEAlgorithm::ES256,
            ECDSACurve::SECP256R1,
            vec![1u8; 31],
            y.to_vec()
        ))
        .is_none());
        assert!(passkey_public_key_sec1(&ec_key(
            COSEAlgorithm::ES256,
            ECDSACurve::SECP256R1,
            x.to_vec(),
            vec![2u8; 33]
        ))
        .is_none());
    }
}
