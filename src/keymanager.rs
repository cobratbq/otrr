// SPDX-License-Identifier: LGPL-3.0-only

use std::cmp::Ordering;

use num_bigint::BigUint;

use crate::{crypto::dh, utils::{self, biguint::ZERO}, OTRError, messages::KeyID};

/// `KeyManager` maintains both our keypairs and received public keys from the other party.
pub struct KeyManager {
    ours: KeypairRotation,
    theirs: PublicKeyRotation,
    our_ctr: Counter,
    their_ctr: Counter,
    /// `used_macs` are MACs that are used and must be revealed in time after key rotation.
    used_macs: Vec<[u8; 20]>,
    /// `old_macs` are MACs that are ready to be revealed as key rotation has occurred.
    old_macs: Vec<u8>,
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        self.old_macs.clear();
    }
}

impl KeyManager {
    pub fn new(ours: (KeyID, dh::Keypair), theirs: (KeyID, BigUint)) -> Self {
        assert_ne!(0, ours.0);
        assert_ne!(0, theirs.0);
        Self {
            ours: KeypairRotation::new(ours.0, ours.1),
            theirs: PublicKeyRotation::new(theirs.0, theirs.1),
            // OTRv3 spec, specifically about top-8-bytes CTR value in Data Message:
            // "This should monotonically increase (as a big-endian value) for
            // each message sent with the same (sender keyid, recipient keyid)
            // pair, and must not be all 0x00."
            our_ctr: Counter::new(),
            their_ctr: Counter::new(),
            used_macs: Vec::new(),
            old_macs: Vec::new(),
        }
    }

    pub fn current_keys(&self) -> (KeyID, &dh::Keypair) {
        self.ours.current()
    }

    pub fn next_keys(&self) -> (KeyID, &dh::Keypair) {
        self.ours.next()
    }

    pub fn our_keys(&self, key_id: KeyID) -> Result<&dh::Keypair, OTRError> {
        self.ours.select(key_id)
    }

    pub fn acknowledge_ours(&mut self, key_id: KeyID) -> Result<(), OTRError> {
        if self.ours.acknowledge(key_id)? {
            self.reveal_used_mac_keys();
            self.reset_counters();
        }
        Ok(())
    }

    pub fn their_current(&self) -> (KeyID, &BigUint) {
        self.theirs.current()
    }

    pub fn their_key(&self, key_id: KeyID) -> Result<&BigUint, OTRError> {
        self.theirs.select(key_id)
    }

    pub fn current_shared_secret(&self) -> BigUint {
        let (_, keypair) = self.ours.current();
        let (_, their_pk) = self.theirs.current();
        keypair.generate_shared_secret(their_pk)
    }

    pub fn register_their_key(&mut self, key_id: KeyID, key: BigUint) -> Result<(), OTRError> {
        if self.theirs.register(key_id, key)? {
            self.reveal_used_mac_keys();
            self.reset_counters();
        }
        Ok(())
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn verify_counter(&mut self, ctr: &[u8; COUNTER_HALF_LEN]) -> Result<(), OTRError> {
        self.their_ctr.verify(ctr)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn take_counter(&mut self) -> [u8; COUNTER_HALF_LEN] {
        self.our_ctr.take()
    }

    pub fn register_used_mac_key(&mut self, mac: [u8; 20]) {
        if !self.used_macs.iter().any(|m| *m == mac) {
            self.used_macs.push(mac);
        }
    }

    fn reveal_used_mac_keys(&mut self) {
        for m in &self.used_macs {
            self.old_macs.extend(m);
        }
        self.used_macs.clear();
        assert_eq!(0, self.old_macs.len() % 20);
    }

    pub fn get_reveal_macs(&mut self) -> Vec<u8> {
        let reveal_macs = std::mem::take(&mut self.old_macs);
        assert_eq!(self.old_macs.len(), 0);
        assert_eq!(0, reveal_macs.len() % 20);
        reveal_macs
    }

    fn reset_counters(&mut self) {
        self.our_ctr.reset();
        self.their_ctr.reset();
    }
}

/// `NUM_KEYS` is the number of keys that are maintained beforing rotating away and forgetting them forever.
const NUM_KEYS: usize = 2;

/// `KeyRotation` manages the rotation of DH-keypairs used by our own client during OTR (single instance) sessions.
struct KeypairRotation {
    keys: [dh::Keypair; NUM_KEYS],
    acknowledged: KeyID,
}

impl Drop for KeypairRotation {
    fn drop(&mut self) {
        self.acknowledged = 0;
    }
}

/// `KeypairRotation` manages the rotation of our own user's DH keypairs.
///
/// The rotation mechanism works by keeping track of the last confirmed key ID.
/// The next key ID is keyID+1 -- deterministic -- so no need to be stored
/// explicitly. Messaging is required to be in-order for OTR, so as soon as
/// a new public key is acknowledged, we can forget the old keypair.
impl KeypairRotation {
    /// New instance of `KeyRotation` struct.
    fn new(initial_keyid: KeyID, initial_key: dh::Keypair) -> Self {
        assert_ne!(0, initial_keyid);
        dh::verify_public_key(&initial_key.public).expect("BUG: public key must be valid.");
        let mut keys: [dh::Keypair; NUM_KEYS] = [dh::Keypair::generate(), dh::Keypair::generate()];
        keys[initial_keyid as usize % NUM_KEYS] = initial_key;
        Self {
            keys,
            acknowledged: initial_keyid,
        }
    }

    /// Get current DH-key, i.e. the key that is acknowledged by the other party.
    fn current(&self) -> (KeyID, &dh::Keypair) {
        let idx = (self.acknowledged as usize) % NUM_KEYS;
        (self.acknowledged, &self.keys[idx])
    }

    /// Get next DH-key (`next_dh`), rotating keys as needed.
    fn next(&self) -> (KeyID, &dh::Keypair) {
        let idx = (self.acknowledged as usize + 1) % NUM_KEYS;
        (self.acknowledged + 1, &self.keys[idx])
    }

    fn select(&self, key_id: KeyID) -> Result<&dh::Keypair, OTRError> {
        assert_ne!(0, key_id);
        if key_id > 0 && self.acknowledged == key_id || self.acknowledged + 1 == key_id {
            // The message for which we request keys must either contain the acknowledged keyid,
            // or the keyid for the next key (because this is the message that acknowledges it).
            Ok(&self.keys[key_id as usize % NUM_KEYS])
        } else {
            // An unknown keyid/key is requested. This is either an error or intentional violation.
            Err(OTRError::ProtocolViolation(
                "Key ID for requested key is not current or previous key.",
            ))
        }
    }

    /// Acknowledge that `key_id` was encountered in a return message from other party. This allows
    /// rotating to the next DH-key. `KeyID`s may be acknowledged multiple times, as long as the
    /// protocol is followed and only the current or next key is acknowledged.
    fn acknowledge(&mut self, key_id: KeyID) -> Result<bool, OTRError> {
        if key_id == self.acknowledged {
            // this keyID was already acknowledged
            Ok(false)
        } else if key_id == self.acknowledged + 1 {
            // this key is indeed new, so updating state
            self.acknowledged = key_id;
            self.keys[(self.acknowledged as usize + 1) % NUM_KEYS] = dh::Keypair::generate();
            Ok(true)
        } else {
            Err(OTRError::ProtocolViolation("unexpected keyID to confirm"))
        }
    }
}

/// Public key rotation, for the other party's public keys.
struct PublicKeyRotation {
    keys: [BigUint; NUM_KEYS],
    id: KeyID,
}

impl Drop for PublicKeyRotation {
    fn drop(&mut self) {
        self.id = 0;
        self.keys = [BigUint::from(0u8), BigUint::from(0u8)];
    }
}

impl PublicKeyRotation {
    fn new(key_id: KeyID, public_key: BigUint) -> Self {
        assert_ne!(0, key_id);
        assert_ne!(*ZERO, public_key);
        let mut keys: [BigUint; NUM_KEYS] = [BigUint::from(0u8), BigUint::from(0u8)];
        keys[key_id as usize % NUM_KEYS] = public_key;
        Self { keys, id: key_id }
    }

    fn current(&self) -> (KeyID, &BigUint) {
        (self.id, &self.keys[self.id as usize % NUM_KEYS])
    }

    fn select(&self, key_id: KeyID) -> Result<&BigUint, OTRError> {
        assert_ne!(0, key_id);
        if key_id > 0 && self.id - 1 == key_id || self.id == key_id {
            // Either they have received or acknowledgement first and this message contains the
            // current keyid or the message was sent earlier and this is still the previous keyid.
            Ok(&self.keys[key_id as usize % NUM_KEYS])
        } else {
            // An unknown keyid/key is requested. This is either an error or intentional violation.
            Err(OTRError::ProtocolViolation(
                "Key ID for requested key is not current or previous key.",
            ))
        }
    }

    /// Register next DH public key. Result `true` indicates a new key was registered, `false`
    /// indicates the key was already known.
    fn register(&mut self, next_id: KeyID, next_key: BigUint) -> Result<bool, OTRError> {
        assert_ne!(0, next_id);
        assert_ne!(*ZERO, next_key);
        if self.id == next_id {
            if self.keys[(self.id as usize) % NUM_KEYS] == next_key {
                Ok(false)
            } else {
                Err(OTRError::ProtocolViolation(
                    "different keys provided for same key ID",
                ))
            }
        } else if self.id + 1 == next_id {
            let idx = (self.id as usize + 1) % NUM_KEYS;
            self.keys[idx] = next_key;
            self.id = next_id;
            Ok(true)
        } else {
            Err(OTRError::ProtocolViolation(
                "Unexpected next DH public key ID",
            ))
        }
    }
}

/// Counter represents either the sending or receiving counter. The counter value is required to be
/// strictly greater than zero. The invariant is uphold in the proper logic sequences for verifying
/// and taking the value:
/// - verify: requires value to be strictly greater than internal state
/// - take: increments internal state before providing value as result
struct Counter([u8; COUNTER_HALF_LEN]);

impl Drop for Counter {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl Counter {
    fn new() -> Counter {
        Counter(COUNTER_INITIAL_VALUE)
    }

    fn reset(&mut self) {
        self.0 = COUNTER_INITIAL_VALUE;
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn verify(&mut self, ctr: &[u8; COUNTER_HALF_LEN]) -> Result<(), OTRError> {
        if utils::bytes::all_zero(ctr) {
            return Err(OTRError::ProtocolViolation(
                "Counter-value cannot be all-zero.",
            ));
        }
        match utils::bytes::cmp(ctr, &self.0) {
            Ordering::Greater => {
                self.0 = *ctr;
                Ok(())
            }
            Ordering::Less | Ordering::Equal => Err(OTRError::ProtocolViolation(
                "Counter value must be strictly larger than previous value.",
            )),
        }
    }

    fn take(&mut self) -> [u8; COUNTER_HALF_LEN] {
        let mut carry: bool;
        for idx in (0..COUNTER_HALF_LEN).rev() {
            (self.0[idx], carry) = self.0[idx].overflowing_add(1);
            if carry {
                continue;
            }
            assert!(utils::bytes::any_nonzero(&self.0));
            return self.0;
        }
        panic!("BUG: wrapped around counter value completely.")
    }
}

// NOTE: see invariant: we initialize to zero such that verify/take can work with strict larger
// value than internal state.
const COUNTER_INITIAL_VALUE: [u8; COUNTER_HALF_LEN] = [0, 0, 0, 0, 0, 0, 0, 0];
const COUNTER_HALF_LEN: usize = 8;

#[cfg(test)]
mod tests {}
