//! Signed wake orders (docs/70-wake-on-lan.md section 5.2).
//! The RMTWAKEv1 domain tag differs from RMTDIRECTIVEv1 so signatures cannot cross.

use crate::directive::{push_lp, uuid_raw};
use rmt_crypto::PublicIdentity;
use serde::de::{value::MapAccessDeserializer, MapAccess, Visitor};
use serde::Deserialize;
use std::marker::PhantomData;
use std::net::Ipv4Addr;

const DOMAIN_TAG: &[u8; 16] = b"RMTWAKEv1\0\0\0\0\0\0\0";
const VERSION: u8 = 1;
const MAX_TTL_MS: i64 = 60_000;
const CLOCK_SKEW_MS: i64 = 30_000;

/// What the relay knows about itself and its current connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeExpectation<'a> {
    pub tenant_id: &'a str,
    pub relay_device_id: &'a str,
    pub relay_key_sha256: [u8; 32],
    pub wake_challenge: [u8; 16],
    pub now_ms: i64,
}

/// The decoded order after all signature, binding and timing checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeOrder {
    pub request_id: [u8; 16],
    pub target_mac: [u8; 6],
    pub network: [u8; 4],
    pub prefix: u8,
    pub gateway_mac: [u8; 6],
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Refusal reasons, in verification order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeError {
    Key,
    Envelope,
    Signature,
    Device,
    Tenant,
    KeyFp,
    Challenge,
    Lifetime,
    NotYetValid,
    Expired,
}

impl WakeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Envelope => "envelope",
            Self::Signature => "signature",
            Self::Device => "device",
            Self::Tenant => "tenant",
            Self::KeyFp => "key_fp",
            Self::Challenge => "challenge",
            Self::Lifetime => "lifetime",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
        }
    }
}

impl std::fmt::Display for WakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wake refused: {}", self.code())
    }
}
impl std::error::Error for WakeError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WakeClaims {
    tenant_id: String,
    relay_device_id: String,
    relay_key_sha256: String,
    wake_challenge: String,
    request_id: String,
    target_mac: String,
    ipv4_network: String,
    gateway_mac: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedWake {
    #[serde(deserialize_with = "deserialize_object")]
    claims: WakeClaims,
    sig: String,
}

/// Preserve the verifier's duplicate-field rejection when signaling deserializes the
/// embedded JSON object before verification. A malformed object becomes a null artifact.
pub(crate) fn deserialize_artifact<'de, D>(deserializer: D) -> Result<serde_json::Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde_json::{Map, Value};

    struct Object<const ENVELOPE: bool>(Value);

    impl<'de, const ENVELOPE: bool> Deserialize<'de> for Object<ENVELOPE> {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct ObjectVisitor<const ENVELOPE: bool>;

            impl<'de, const ENVELOPE: bool> Visitor<'de> for ObjectVisitor<ENVELOPE> {
                type Value = Object<ENVELOPE>;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a wake JSON object")
                }

                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut input: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut object = Map::new();
                    let mut duplicate = false;
                    while let Some(key) = input.next_key::<String>()? {
                        let value = if ENVELOPE && key == "claims" {
                            input.next_value::<Artifact<false>>()?.value()
                        } else {
                            input.next_value::<Value>()?
                        };
                        duplicate |= object.insert(key, value).is_some();
                    }
                    let invalid_claims =
                        ENVELOPE && object.get("claims").is_some_and(Value::is_null);
                    Ok(Object(if duplicate || invalid_claims {
                        Value::Null
                    } else {
                        Value::Object(object)
                    }))
                }
            }

            deserializer.deserialize_map(ObjectVisitor::<ENVELOPE>)
        }
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Artifact<const ENVELOPE: bool> {
        Object(Object<ENVELOPE>),
        Other(Value),
    }

    impl<const ENVELOPE: bool> Artifact<ENVELOPE> {
        fn value(self) -> Value {
            match self {
                Self::Object(object) => object.0,
                Self::Other(value) => value,
            }
        }
    }

    Artifact::<true>::deserialize(deserializer).map(Artifact::value)
}

pub(crate) fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(PhantomData))
}

pub(crate) fn lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode_to_slice(s, &mut bytes).ok()?;
    Some(bytes)
}

fn mac(s: &str) -> Option<[u8; 6]> {
    let mut parts = s.split(':');
    let mut bytes = [0; 6];
    for byte in &mut bytes {
        *byte = lower_hex::<1>(parts.next()?)?[0];
    }
    (parts.next().is_none() && bytes != [0; 6] && bytes[0] & 1 == 0).then_some(bytes)
}

impl WakeClaims {
    fn order(&self) -> Option<WakeOrder> {
        let (addr, bits) = self.ipv4_network.split_once('/')?;
        let addr: Ipv4Addr = addr.parse().ok()?;
        let prefix: u8 = bits.parse().ok()?;
        if !(16..=30).contains(&prefix)
            || format!("{addr}/{prefix}") != self.ipv4_network
            || u32::from(addr) & (u32::MAX >> prefix) != 0
            || self.request_id.bytes().any(|b| b.is_ascii_uppercase())
        {
            return None;
        }
        Some(WakeOrder {
            request_id: uuid_raw(&self.request_id)?,
            target_mac: mac(&self.target_mac)?,
            network: addr.octets(),
            prefix,
            gateway_mac: mac(&self.gateway_mac)?,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
        })
    }

    fn preimage(&self, fp: &[u8; 32], challenge: &[u8; 16], order: &WakeOrder) -> Option<Vec<u8>> {
        let tenant = uuid_raw(&self.tenant_id)?;
        if self.tenant_id.bytes().any(|b| b.is_ascii_uppercase())
            || self.relay_device_id.is_empty()
            || u32::try_from(self.relay_device_id.len()).is_err()
        {
            return None;
        }
        let mut w = Vec::new();
        w.extend_from_slice(DOMAIN_TAG);
        w.push(VERSION);
        w.extend_from_slice(&tenant);
        push_lp(&mut w, self.relay_device_id.as_bytes());
        w.extend_from_slice(fp);
        w.extend_from_slice(challenge);
        w.extend_from_slice(&order.request_id);
        w.extend_from_slice(&order.target_mac);
        w.extend_from_slice(&order.network);
        w.push(order.prefix);
        w.extend_from_slice(&order.gateway_mac);
        w.extend_from_slice(&order.issued_at_ms.to_be_bytes());
        w.extend_from_slice(&order.expires_at_ms.to_be_bytes());
        Some(w)
    }
}

/// Verify the order against the pinned directive key and current relay context.
pub fn verify_wake(
    pinned_public_key: &[u8],
    artifact: &[u8],
    exp: &WakeExpectation<'_>,
) -> Result<WakeOrder, WakeError> {
    if pinned_public_key.len() != 32 {
        return Err(WakeError::Key);
    }
    let key =
        PublicIdentity::from_hex(&hex::encode(pinned_public_key)).map_err(|_| WakeError::Key)?;
    let mut json = serde_json::Deserializer::from_slice(artifact);
    let signed: SignedWake = deserialize_object(&mut json).map_err(|_| WakeError::Envelope)?;
    json.end().map_err(|_| WakeError::Envelope)?;
    let c = signed.claims;
    let sig = lower_hex(&signed.sig).ok_or(WakeError::Envelope)?;
    let fp = lower_hex(&c.relay_key_sha256).ok_or(WakeError::Envelope)?;
    let challenge = lower_hex(&c.wake_challenge).ok_or(WakeError::Envelope)?;
    let order = c.order().ok_or(WakeError::Envelope)?;
    let msg = c
        .preimage(&fp, &challenge, &order)
        .ok_or(WakeError::Envelope)?;
    key.verify(&msg, &sig).map_err(|_| WakeError::Signature)?;
    if c.relay_device_id != exp.relay_device_id {
        return Err(WakeError::Device);
    }
    if !c.tenant_id.eq_ignore_ascii_case(exp.tenant_id) {
        return Err(WakeError::Tenant);
    }
    if fp != exp.relay_key_sha256 {
        return Err(WakeError::KeyFp);
    }
    if challenge != exp.wake_challenge {
        return Err(WakeError::Challenge);
    }
    if !matches!(
        order.expires_at_ms.checked_sub(order.issued_at_ms),
        Some(1..=MAX_TTL_MS)
    ) {
        return Err(WakeError::Lifetime);
    }
    if order.issued_at_ms > exp.now_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err(WakeError::NotYetValid);
    }
    if exp.now_ms >= order.expires_at_ms {
        return Err(WakeError::Expired);
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../testdata/wake-vectors.json");

    #[test]
    fn every_wake_vector_returns_the_documented_outcome() {
        let vectors: Value = serde_json::from_str(VECTORS).unwrap();
        for case in vectors["wake_vectors"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let exp = &case["expectation"];
            let pinned = hex::decode(case["pinned_public_key_hex"].as_str().unwrap()).unwrap();
            let artifact = case["artifact"].as_str().unwrap();
            let result = verify_wake(
                &pinned,
                artifact.as_bytes(),
                &WakeExpectation {
                    tenant_id: exp["tenant_id"].as_str().unwrap(),
                    relay_device_id: exp["relay_device_id"].as_str().unwrap(),
                    relay_key_sha256: lower_hex(exp["relay_key_sha256"].as_str().unwrap()).unwrap(),
                    wake_challenge: lower_hex(exp["wake_challenge"].as_str().unwrap()).unwrap(),
                    now_ms: exp["now_ms"].as_i64().unwrap(),
                },
            );
            let got = result.as_ref().map_or_else(|e| e.code(), |_| "ok");
            assert_eq!(got, case["expect"].as_str().unwrap(), "vector {name:?}");
            if let Some(want) = case["preimage_hex"].as_str() {
                let c = serde_json::from_str::<SignedWake>(artifact).unwrap().claims;
                let fp = lower_hex(&c.relay_key_sha256).unwrap();
                let challenge = lower_hex(&c.wake_challenge).unwrap();
                let order = result.unwrap();
                let msg = c.preimage(&fp, &challenge, &order).unwrap();
                assert_eq!(hex::encode(msg), want, "vector {name:?}");
            }
        }
    }
}
