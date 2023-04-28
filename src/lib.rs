use std::{fmt::Display, str::FromStr};

use bytes::Bytes;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

/// A MIP-102 encoded wallet secret. The Display and FromStr methods implement the "succinct" encoding. The FromStr method also works for other encodings, as it tries many ways.
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct WalletSecret {
    pub key_type: KeyType,
    pub payload: Bytes,
}

impl Display for WalletSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut to_encode = Vec::with_capacity(self.payload.len() + 1);
        to_encode.push(self.key_type as u8);
        to_encode.extend_from_slice(&self.payload);
        ("SK-".to_string() + &base32::encode(base32::Alphabet::Crockford, &to_encode)).fmt(f)
    }
}

#[derive(Error, Debug)]
pub enum WalletSecretParseError {
    #[error("missing 'SK-' prefix")]
    MissingPrefix,
    #[error("base32 parse failure")]
    Base32ParseFailure,
    #[error("unknown key type {0}")]
    UnknownKeyType(u8),
}

fn parse_old_melwalletd(s: &str) -> Option<WalletSecret> {
    let raw_parsed = base32::decode(base32::Alphabet::Crockford, s)?;
    let raw_parsed: [u8; 32] = raw_parsed.try_into().ok()?;
    // we must painstakingly reconstruct
    let secret = ed25519_consensus::SigningKey::from(raw_parsed);
    let public: ed25519_consensus::VerificationKey = (&secret).into();
    let mut vv = vec![0u8; 64];
    vv[0..32].copy_from_slice(&secret.to_bytes());
    vv[32..].copy_from_slice(&public.to_bytes());
    Some(WalletSecret {
        key_type: KeyType::Ed25519Standard,
        payload: vv.into(),
    })
}

impl FromStr for WalletSecret {
    type Err = WalletSecretParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("SK-") {
            if let Some(val) = parse_old_melwalletd(s) {
                return Ok(val);
            }
            return Err(WalletSecretParseError::MissingPrefix);
        }

        let decoded = base32::decode(base32::Alphabet::Crockford, &s[3..])
            .ok_or(WalletSecretParseError::Base32ParseFailure)?;

        if decoded.is_empty() {
            return Err(WalletSecretParseError::Base32ParseFailure);
        }

        let key_type = decoded[0];
        let payload = decoded[1..].to_vec().into();

        Ok(Self {
            key_type: KeyType::from_u8(key_type)
                .ok_or(WalletSecretParseError::UnknownKeyType(key_type))?,
            payload,
        })
    }
}

/// A key type.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Ord, Eq, FromPrimitive)]
#[repr(u8)]
pub enum KeyType {
    Reserved = 0x00,
    Ed25519Standard = 0x01,
}
