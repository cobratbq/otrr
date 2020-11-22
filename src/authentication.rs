use std::rc::Rc;

use crate::{crypto, encoding::OTRMessage, Message, OTRError, MAC};

pub fn new_context() -> AKEContext {
    return AKEContext {
        state: AKEState::None,
    };
}

pub struct AKEContext {
    state: AKEState,
}

enum AKEState {
    None,
    AwaitingDHKey {
        r: [u8; 16],
        our_dh_keypair: Rc<crypto::DH::Keypair>,
    },
    AwaitingRevealSignature {
        our_dh_keypair: Rc<crypto::DH::Keypair>,
        gx_encrypted: Vec<u8>,
        gx_hashed: Vec<u8>,
    },
    AwaitingSignature,
}

impl AKEContext {
    pub fn handle_commit(
        &mut self,
        gx_encrypted: Vec<u8>,
        gx_hashed: Vec<u8>,
    ) -> Result<OTRMessage, OTRError> {
        return match &self.state {
            AKEState::None => {
                // Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
                let keypair = crypto::DH::generate();
                let dhkey = OTRMessage::DHKey {
                    gy: keypair.public.clone(),
                };
                self.state = AKEState::AwaitingRevealSignature {
                    our_dh_keypair: Rc::new(keypair),
                    gx_encrypted,
                    gx_hashed,
                };
                Ok(dhkey)
            }
            AKEState::AwaitingDHKey { r, our_dh_keypair } => {
                // This is the trickiest transition in the whole protocol. It indicates that you have already sent a
                // D-H Commit message to your correspondent, but that he either didn't receive it, or just didn't
                // receive it yet, and has sent you one as well. The symmetry will be broken by comparing the hashed gx
                // you sent in your D-H Commit Message with the one you received, considered as 32-byte unsigned
                // big-endian values.
                let our_gx_hashed = temp_hash_mpi(&our_dh_keypair.public);
                let our_hash = num_bigint::BigUint::from_bytes_be(&our_gx_hashed);
                let their_hash = num_bigint::BigUint::from_bytes_be(&gx_hashed);
                return if our_hash.gt(&their_hash) {
                    // Ignore the incoming D-H Commit message, but resend your D-H Commit message.
                    let our_gx_encrypted = temp_encrypt_mpi(&r, &our_dh_keypair.public);
                    let dhcommit = OTRMessage::DHCommit {
                        gx_encrypted: our_gx_encrypted,
                        gx_hashed: our_gx_hashed,
                    };
                    Ok(dhcommit)
                } else {
                    // Forget your old gx value that you sent (encrypted) earlier, and pretend you're in
                    // AUTHSTATE_NONE; i.e. reply with a D-H Key Message, and transition authstate to
                    // AUTHSTATE_AWAITING_REVEALSIG.
                    self.state = AKEState::None;
                    self.handle_commit(gx_encrypted, gx_hashed)
                };
            }
            AKEState::AwaitingRevealSignature {
                our_dh_keypair,
                gx_encrypted,
                gx_hashed,
            } => {
                // Retransmit your D-H Key Message (the same one as you sent when you entered
                // AUTHSTATE_AWAITING_REVEALSIG). Forget the old D-H Commit message, and use this new one instead.
                // There are a number of reasons this might happen, including:
                // - Your correspondent simply started a new AKE.
                // - Your correspondent resent his D-H Commit message, as specified above.
                // - On some networks, like AIM, if your correspondent is logged in multiple times, each of his clients
                //   will send a D-H Commit Message in response to a Query Message; resending the same D-H Key Message
                //   in response to each of those messages will prevent compounded confusion, since each of his clients
                //   will see each of the D-H Key Messages you send. [And the problem gets even worse if you are each
                //   logged in multiple times.]
                let dhkey = OTRMessage::DHKey {
                    gy: our_dh_keypair.public.clone(),
                };
                self.state = AKEState::AwaitingRevealSignature {
                    our_dh_keypair: Rc::clone(our_dh_keypair),
                    gx_encrypted: gx_encrypted.clone(),
                    gx_hashed: gx_hashed.clone(),
                };
                Ok(dhkey)
            }
            AKEState::AwaitingSignature => {
                // Reply with a new D-H Key message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
                let our_dh_keypair = crypto::DH::generate();
                let dhkey = OTRMessage::DHKey {
                    gy: our_dh_keypair.public.clone(),
                };
                self.state = AKEState::AwaitingRevealSignature {
                    our_dh_keypair: Rc::new(our_dh_keypair),
                    gx_encrypted,
                    gx_hashed,
                };
                Ok(dhkey)
            }
        };
    }

    pub fn handle_key(&mut self, gy: num_bigint::BigUint) -> Result<Message, OTRError> {
        todo!()
    }

    pub fn handle_reveal_signature(
        &mut self,
        key: Vec<u8>,
        signature_encrypted: Vec<u8>,
        signature_mac: MAC,
    ) -> Result<Message, OTRError> {
        todo!()
    }

    pub fn handle_signature(
        &mut self,
        signature_encrypted: Vec<u8>,
        signature_mac: MAC,
    ) -> Result<Message, OTRError> {
        todo!()
    }
}

fn temp_hash_mpi(v: &num_bigint::BigUint) -> Vec<u8> {
    todo!(
        "Replace this with the various real function calls for encoding and hashing the MPI-value."
    )
}

fn temp_encrypt_mpi(key: &[u8; 16], v: &num_bigint::BigUint) -> Vec<u8> {
    todo!("Implement encrypting data with provided key.")
}
