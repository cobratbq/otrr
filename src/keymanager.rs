use num::{BigUint, Zero};

use crate::{crypto::DH, encoding::KeyID, OTRError};

/// KeyManager maintains both our keypairs and received public keys from the other party.
pub struct KeyManager {
    ours: KeypairRotation,
    theirs: PublicKeyRotation,
    ctr: Counter,
}

// TODO double-check counter reset logic.
impl KeyManager {
    pub fn new(ours: (KeyID, DH::Keypair), theirs: (KeyID, BigUint)) -> Self {
        Self {
            ours: KeypairRotation::new(ours.0, ours.1),
            theirs: PublicKeyRotation::new(theirs.0, theirs.1),
            // FIXME correctly initialize counter for first use after AKE (cannot be 0)
            // OTRv3 spec, specifically about top-8-bytes CTR value in Data Message:
            // "This should monotonically increase (as a big-endian value) for
            // each message sent with the same (sender keyid, recipient keyid)
            // pair, and must not be all 0x00."
            ctr: Counter::new(),
        }
    }

    pub fn current_keys(&self) -> (KeyID, &DH::Keypair) {
        self.ours.current()
    }

    pub fn next_keys(&self) -> (KeyID, &DH::Keypair) {
        self.ours.next()
    }

    pub fn acknowledge_ours(&mut self, key_id: KeyID) -> Result<(), OTRError> {
        self.ours.acknowledge(key_id)?;
        // FIXME was acknowledge successful/impactful?
        self.ctr.reset();
        Ok(())
    }

    pub fn their_current(&self) -> (KeyID, &BigUint) {
        self.theirs.current()
    }

    pub fn take_shared_secret(&self) -> BigUint {
        let (_, keypair) = self.ours.current();
        let (_, their_pk) = self.theirs.current();
        keypair.generate_shared_secret(&their_pk)
    }

    pub fn register_their_next(&mut self, key_id: KeyID, key: BigUint) -> Result<(), OTRError> {
        self.theirs.register(key_id, key)?;
        // FIXME was register successful/impactful?
        self.ctr.reset();
        Ok(())
    }

    pub fn take_counter(&mut self) -> [u8; COUNTER_HALF_LEN] {
        self.ctr.take()
    }

    pub fn get_used_macs(&mut self) -> Vec<u8> {
        todo!("To be implemented")
    }
}

/// NUM_KEYS is the number of keys that are maintained beforing rotating away and forgetting them forever.
const NUM_KEYS: usize = 2;

/// KeyRotation manages the rotation of DH-keypairs used by our own client during OTR (single instance) sessions.
struct KeypairRotation {
    keys: [DH::Keypair; NUM_KEYS],
    acknowledged: KeyID,
}

/// KeypairRotation manages the rotation of our own user's DH keypairs.
///
/// The rotation mechanism works by keeping track of the last confirmed key ID.
/// The next key ID is keyID+1 -- deterministic -- so no need to be stored
/// explicitly. Messaging is required to be in-order for OTR, so as soon as
/// a new public key is acknowledged, we can forget the old keypair.
// FIXME need to check that illegal values (keypair, keyid) cannot happen. (assertions?)
impl KeypairRotation {
    /// New instance of KeyRotation struct.
    // TODO neither generated keypair is actually used. Create a dummy "zero"-type (risk?) or ignore as insignificant?
    fn new(initial_keyid: KeyID, initial_key: DH::Keypair) -> Self {
        assert!(initial_keyid > 0);
        let mut keys: [DH::Keypair; NUM_KEYS] = [DH::Keypair::generate(), DH::Keypair::generate()];
        keys[initial_keyid as usize % NUM_KEYS] = initial_key;
        Self {
            keys,
            acknowledged: initial_keyid,
        }
    }

    /// Get current DH-key, i.e. the key that is acknowledged by the other party.
    fn current(&self) -> (KeyID, &DH::Keypair) {
        let idx = (self.acknowledged as usize) % NUM_KEYS;
        (self.acknowledged, &self.keys[idx])
    }

    /// Get next DH-key (`next_dh`), rotating keys as needed.
    fn next(&self) -> (KeyID, &DH::Keypair) {
        let idx = (self.acknowledged as usize + 1) % NUM_KEYS;
        (self.acknowledged + 1, &self.keys[idx])
    }

    /// Acknowledge that a keyID was encountered in a return message from other
    /// party. This allows rotating to the next DH-key. KeyIDs may be
    /// acknowledged multiple times, as long as the protocol is followed and
    /// only the current or next key is acknowledged.
    fn acknowledge(&mut self, key_id: KeyID) -> Result<(), OTRError> {
        if key_id == self.acknowledged {
            // this keyID was already acknowledged
            Ok(())
        } else if key_id == self.acknowledged + 1 {
            self.acknowledged = key_id;
            // TODO currently no explicit zeroing/cleaning
            self.keys[(self.acknowledged as usize + 1) % NUM_KEYS] = DH::Keypair::generate();
            Ok(())
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

impl PublicKeyRotation {
    fn new(key_id: KeyID, public_key: BigUint) -> Self {
        assert!(key_id > 0);
        assert_ne!(public_key, BigUint::zero());
        let mut keys: [BigUint; NUM_KEYS] = [BigUint::zero(), BigUint::zero()];
        keys[key_id as usize % NUM_KEYS] = public_key;
        Self { keys, id: key_id }
    }

    pub fn current(&self) -> (KeyID, &BigUint) {
        (self.id, &self.keys[self.id as usize % NUM_KEYS])
    }

    fn verify(&self, key_id: KeyID, public_key: BigUint) -> Result<(), OTRError> {
        let idx = key_id as usize % NUM_KEYS;
        return if self.keys[idx] == public_key {
            Ok(())
        } else {
            Err(OTRError::ProtocolViolation(
                "Failed to verify DH public key with local key cache.",
            ))
        };
    }

    /// Register next DH public key.
    fn register(&mut self, next_id: KeyID, next_key: BigUint) -> Result<(), OTRError> {
        assert_ne!(next_key, BigUint::zero());
        return if self.id == next_id {
            // TODO probably needs constant-time comparison
            if self.keys[(self.id as usize) % NUM_KEYS] == next_key {
                Ok(())
            } else {
                Err(OTRError::ProtocolViolation(
                    "different keys provided for same key ID",
                ))
            }
        } else if self.id + 1 == next_id {
            let idx = (self.id as usize + 1) % NUM_KEYS;
            // FIXME is this overwriting sufficiently effective or should we clean/zero the memory first?
            self.keys[idx] = next_key;
            self.id = next_id;
            Ok(())
        } else {
            Err(OTRError::ProtocolViolation(
                "Unexpected next DH public key ID",
            ))
        };
    }
}

const COUNTER_HALF_LEN: usize = 8;
const COUNTER_INITIAL_VALUE: [u8; COUNTER_HALF_LEN] = [0, 0, 0, 0, 0, 0, 0, 1];

struct Counter([u8; COUNTER_HALF_LEN]);

// TODO confirm correct type and sizes
impl Counter {
    fn new() -> Counter {
        Counter(COUNTER_INITIAL_VALUE)
    }

    fn reset(&mut self) {
        self.0 = COUNTER_INITIAL_VALUE;
    }

    fn take(&mut self) -> [u8; COUNTER_HALF_LEN] {
        let result = self.0;
        for idx in (0..COUNTER_HALF_LEN).rev() {
            let (val, carry) = self.0[idx].overflowing_add(1);
            self.0[idx] = val;
            if carry {
                continue;
            }
            return result;
        }
        // TODO This is very unlikely to happen, so just panic and make this a problem for the future.
        panic!("BUG: wrapped around counter value completely.")
    }
}

#[cfg(test)]
mod tests {}
