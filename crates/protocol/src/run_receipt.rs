//! Agent-signed run receipts (docs/72-toolbox-run-receipts.md section 4.3).

use crate::directive::{push_lp, uuid_raw};
use crate::wake::{deserialize_object, lower_hex};
use rmt_crypto::{Identity, PublicIdentity};
use serde::{Deserialize, Serialize};

const DOMAIN_TAG: &[u8; 16] = b"RMTRUNRCPTv1\0\0\0\0";
const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReceiptClaims {
    pub tenant_id: String,
    pub device_id: String,
    pub session_id: String,
    pub request_id: String,
    pub shell: String,
    pub run_as: String,
    pub exec_sha256: String,
    pub outcome: String,
    #[serde(deserialize_with = "deserialize_exit_code")]
    pub exit_code: Option<i32>,
    pub truncated: bool,
    pub finished_at_ms: i64,
}

// A custom deserializer makes the field required while allowing explicit null.
fn deserialize_exit_code<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i32>, D::Error> {
    Option::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRunReceipt {
    #[serde(deserialize_with = "deserialize_object")]
    pub claims: RunReceiptClaims,
    pub sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunReceiptError {
    Key,
    Envelope,
    Signature,
}

impl RunReceiptError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Envelope => "envelope",
            Self::Signature => "signature",
        }
    }
}

impl std::fmt::Display for RunReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "run receipt refused: {}", self.code())
    }
}

impl std::error::Error for RunReceiptError {}

fn canonical_uuid(s: &str) -> Result<[u8; 16], RunReceiptError> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(RunReceiptError::Envelope);
    }
    uuid_raw(s).ok_or(RunReceiptError::Envelope)
}

/// Encode validated claims into the canonical signed bytes.
pub fn preimage(c: &RunReceiptClaims) -> Result<Vec<u8>, RunReceiptError> {
    use RunReceiptError::Envelope;

    let tenant = canonical_uuid(&c.tenant_id)?;
    let session = canonical_uuid(&c.session_id)?;
    let request = canonical_uuid(&c.request_id)?;
    if c.device_id.len() > 256 {
        return Err(Envelope);
    }

    let shell = match c.shell.as_str() {
        "powershell" => 1,
        "cmd" => 2,
        _ => return Err(Envelope),
    };
    let run_as = match c.run_as.as_str() {
        "system" => 1,
        "user" => 2,
        _ => return Err(Envelope),
    };
    let exec_hash = lower_hex::<32>(&c.exec_sha256).ok_or(Envelope)?;
    let (outcome, exit_code) = match (c.outcome.as_str(), c.exit_code, c.truncated) {
        ("exited", Some(code), _) => (1, code),
        ("timed_out", Some(code), _) => (2, code),
        ("start_failed", None, false) => (3, 0),
        _ => return Err(Envelope),
    };

    let mut w = Vec::new();
    w.extend_from_slice(DOMAIN_TAG);
    w.push(VERSION);
    w.extend_from_slice(&tenant);
    push_lp(&mut w, c.device_id.as_bytes());
    w.extend_from_slice(&session);
    w.extend_from_slice(&request);
    w.extend_from_slice(&[shell, run_as]);
    w.extend_from_slice(&exec_hash);
    w.push(outcome);
    w.extend_from_slice(&exit_code.to_be_bytes());
    w.push(u8::from(c.truncated));
    w.extend_from_slice(&c.finished_at_ms.to_be_bytes());
    Ok(w)
}

pub fn sign(
    device_key: &Identity,
    claims: &RunReceiptClaims,
) -> Result<SignedRunReceipt, RunReceiptError> {
    sign_with(claims, |msg| device_key.sign(msg))
}

/// Sign using the enrolled device signer, which owns the key material.
pub fn sign_with(
    claims: &RunReceiptClaims,
    signer: impl FnOnce(&[u8]) -> [u8; 64],
) -> Result<SignedRunReceipt, RunReceiptError> {
    let msg = preimage(claims)?;
    Ok(SignedRunReceipt {
        claims: claims.clone(),
        sig: hex::encode(signer(&msg)),
    })
}

pub fn verify(
    device_public_key: &[u8; 32],
    signed: &[u8],
) -> Result<RunReceiptClaims, RunReceiptError> {
    use RunReceiptError::{Envelope, Key, Signature};

    let key = PublicIdentity::from_hex(&hex::encode(device_public_key)).map_err(|_| Key)?;
    let mut json = serde_json::Deserializer::from_slice(signed);
    let receipt: SignedRunReceipt = deserialize_object(&mut json).map_err(|_| Envelope)?;
    json.end().map_err(|_| Envelope)?;
    let sig = lower_hex(&receipt.sig).ok_or(Envelope)?;
    let msg = preimage(&receipt.claims)?;
    key.verify(&msg, &sig).map_err(|_| Signature)?;
    Ok(receipt.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_receipt_golden_vectors() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/run-receipt-vectors.json")).unwrap();
        let identity = Identity::from_seed(&[0x22; 32]);
        let pubkey = lower_hex(file["device_public_key_hex"].as_str().unwrap()).unwrap();
        assert_eq!(identity.public_hex(), hex::encode(pubkey));
        for case in file["run_receipt_vectors"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let artifact = case["artifact"].as_str().unwrap();
            let result = verify(&pubkey, artifact.as_bytes());
            let got = result.as_ref().map_or_else(|err| err.code(), |_| "ok");
            assert_eq!(got, case["expect"].as_str().unwrap(), "vector {name:?}");
            if let Ok(claims) = result {
                let expected: SignedRunReceipt = serde_json::from_str(artifact).unwrap();
                assert_eq!(
                    hex::encode(preimage(&claims).unwrap()),
                    case["preimage_hex"].as_str().unwrap(),
                    "vector {name:?}"
                );
                assert_eq!(sign(&identity, &claims).unwrap(), expected, "vector {name:?}");
            }
        }
    }
}
