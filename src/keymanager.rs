use num::BigUint;

use crate::{crypto::DH, encoding::KeyID, OTRError};

/// KeyManager maintains both our keypairs and received public keys from the other party.
pub struct KeyManager {
    ours: KeyRotation,
    theirs: (KeyID, BigUint),
    // FIXME confirm correct type and sizes
    ctr: [u8; 16],
}

impl KeyManager {
    pub fn new() -> Self {
        // FIXME implement new KeyManager creation
        todo!("Implement construction of keymanager")
    }

    pub fn acknowledge_ours(&mut self, key_id: KeyID) -> Result<(), OTRError> {
        self.ours.acknowledge(key_id)
    }

    pub fn set_theirs(&mut self, key_id: KeyID, key: BigUint) {
        // FIXME 'their_keyid-1' can be needed if consecutive message arrives before we have a chance to acknowledge their next_dh public key, but we had updated our keymanager already.
        self.theirs = (key_id, key);
    }
}

/// KeyRotation manages the rotation of DH-keypairs used by our own client during OTR sessions.
struct KeyRotation {
    keys: [DH::Keypair; NUM_KEYS],
    acknowledged: KeyID,
}

impl KeyRotation {
    /// New instance of KeyRotation struct.
    // TODO neither generated keypair is actually used. Create a dummy "zero"-type (risk?) or ignore as insignificant?
    fn new(initial_key: DH::Keypair, initial_keyid: KeyID) -> Self {
        let mut keys: [DH::Keypair; NUM_KEYS] = [DH::Keypair::generate(), DH::Keypair::generate()];
        keys[initial_keyid as usize % NUM_KEYS] = initial_key;
        KeyRotation {
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
            self.keys[(self.acknowledged as usize + 1) % NUM_KEYS] = DH::Keypair::generate();
            Ok(())
        } else {
            Err(OTRError::ProtocolViolation("unexpected keyID to confirm"))
        }
    }
}

/// NUM_KEYS is the number of keys that are maintained beforing rotating away and forgetting them forever.
const NUM_KEYS: usize = 2;
