use num::{BigUint, Zero};

use crate::{crypto::DH, encoding::KeyID, OTRError};

/// NUM_KEYS is the number of keys that are maintained beforing rotating away and forgetting them forever.
const NUM_KEYS: usize = 2;

/// KeyManager maintains both our keypairs and received public keys from the other party.
pub struct KeyManager {
    ours: KeypairRotation,
    theirs: PublicKeyRotation,
    // FIXME confirm correct type and sizes
    ctr: Counter,
}

impl KeyManager {
    pub fn new(ours: (KeyID, DH::Keypair), theirs: (KeyID, BigUint)) -> Self {
        // FIXME implement new KeyManager creation
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

    pub fn acknowledge_ours(&mut self, key_id: KeyID) -> Result<(), OTRError> {
        self.ours.acknowledge(key_id)
        // FIXME determine if we can reset the counter!
    }

    pub fn register_their_next(&mut self, key_id: KeyID, key: BigUint) {
        self.theirs.register(key)
        // FIXME determine if we can reset the counter!
    }
}

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
    fn next(&mut self) -> (KeyID, &DH::Keypair) {
        let idx = (self.acknowledged as usize + 1) % NUM_KEYS;
        (self.acknowledged + 1, &self.keys[idx])
    }

    /// Acknowledge that a keyID was encountered in a return message from other
    /// party. This allows rotating to the next DH-key. KeyIDs may be
    /// acknowledged multiple times, as long as the protocol is followed and
    /// only the current or next key is acknowledged.
    fn acknowledge(&mut self, key_id: KeyID) -> Result<(), OTRError> {
        if key_id == self.acknowledged {
            // this keyID was already acknowledged otherwise we would not rotate away
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

    fn verify(&mut self, key_id: KeyID, public_key: BigUint) -> Result<(), OTRError> {
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
    fn register(&mut self, next_key: BigUint) {
        assert_ne!(next_key, BigUint::zero());
        // FIXME take into account same next_dh value can be provided multiple times.
        let idx = (self.id as usize + 1) % NUM_KEYS;
        // FIXME is this overwriting sufficiently effective or should we clean/zero the memory first?
        self.keys[idx] = next_key;
        self.id += 1;
    }
}

const COUNTER_LEN: usize = 16;
const COUNTER_INITIAL_VALUE: [u8; COUNTER_LEN] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

struct Counter([u8; COUNTER_LEN]);

// FIXME counter needs to adjust for top-8-bytes provided in data messages.
// FIXME OTR-spec: "The initial counter is a 16-byte value whose first 8 bytes are the above "top half of counter init" value, and whose last 8 bytes are all 0x00."
impl Counter {
    fn new() -> Counter {
        Counter(COUNTER_INITIAL_VALUE)
    }

    fn reset(&mut self) {
        self.0 = COUNTER_INITIAL_VALUE;
    }

    fn take(&mut self) -> [u8; COUNTER_LEN] {
        let result = self.0;
        for i in 0..COUNTER_LEN {
            let idx = COUNTER_LEN - 1 - i;
            let (val, carry) = self.0[idx].overflowing_add(1);
            self.0[idx] = val;
            if carry {
                continue;
            }
            return result;
        }
        panic!("BUG: wrapped around complete counter value. This is very unlikely to ever happen.")
    }
}
