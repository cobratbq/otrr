use std::rc::Rc;

use crypto::{AES128, DH, SHA256};
use num_bigint::BigUint;

use crate::{MAC, Signature, crypto::{self, CryptoError, DSA}, encoding::{OTRMessage, new_decoder, new_encoder}};

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
        r: AES128::Key,
        our_dh_keypair: Rc<DH::Keypair>,
    },
    AwaitingRevealSignature {
        our_dh_keypair: Rc<DH::Keypair>,
        gx_encrypted: Vec<u8>,
        gx_hashed: Vec<u8>,
    },
    AwaitingSignature {
        our_dh_keypair: Rc<DH::Keypair>,
        key: AES128::Key,
        gy: BigUint,
        secrets: DH::DerivedSecrets,
    },
}

// FIXME check verification of public keys everywhere.
// FIXME check updating of state everywhere where necessary.
impl AKEContext {
    pub fn handle_commit(
        &mut self,
        gx_encrypted: Vec<u8>,
        gx_hashed: Vec<u8>,
    ) -> Result<OTRMessage, AKEError> {
        return match &self.state {
            AKEState::None => {
                // Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
                let keypair = DH::generate();
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
                let gxmpi = new_encoder().write_mpi(&our_dh_keypair.public).to_vec();
                let our_gxmpi_hashed = SHA256::digest(&gxmpi);
                let our_hash = BigUint::from_bytes_be(&our_gxmpi_hashed);
                let their_hash = BigUint::from_bytes_be(&gx_hashed);
                return if our_hash.gt(&their_hash) {
                    // Ignore the incoming D-H Commit message, but resend your D-H Commit message.
                    let our_gx_encrypted = AES128::encrypt(r, &[0u8; 16], &gxmpi);
                    let dhcommit = OTRMessage::DHCommit {
                        gx_encrypted: our_gx_encrypted,
                        gx_hashed: Vec::from(our_gxmpi_hashed),
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
            AKEState::AwaitingSignature{
                our_dh_keypair: _,
                key: _,
                gy: _,
                secrets: _,
            } => {
                // Reply with a new D-H Key message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
                let our_dh_keypair = DH::generate();
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

    pub fn handle_key(&mut self, gy: &BigUint) -> Result<OTRMessage, AKEError> {
        return match self.state {
            AKEState::None => {
                // Ignore the message.
                Err(AKEError::MessageIgnored)
            }
            AKEState::AwaitingDHKey { r, our_dh_keypair } => {
                DH::verify_public_key(gy)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                // Reply with a Reveal Signature Message and transition authstate to AUTHSTATE_AWAITING_SIG.
                let secrets = our_dh_keypair.derive_secrets(gy);
                // TODO consider random starting key-id for initial key-id. (Spec: keyid > 0)
                let pub_b: DSA::PublicKey;
                let keyid_b = 1u32;
                let m_b = SHA256::hmac(&secrets.m1, &new_encoder()
                    .write_mpi(&our_dh_keypair.public)
                    .write_mpi(gy)
                // FIXME acquire DSA public key from host, write to m_b.
                    .write_public_key(&pub_b)
                    .write_int(keyid_b)
                    .to_vec());
                // FIXME replace with actual signature calculation.
                let sig_b: Signature = [0u8;40];
                let x_b = new_encoder()
                    .write_public_key(&pub_b)
                    .write_int(keyid_b)
                    .write_signature(&sig_b)
                    .to_vec();
                let enc_b = new_encoder()
                    .write_data(&AES128::encrypt(&secrets.c, &[0u8;16], &x_b))
                    .to_vec();
                self.state = AKEState::AwaitingSignature{
                    our_dh_keypair: our_dh_keypair,
                    gy: *gy,
                    key: r,
                    secrets,
                };
                Ok(OTRMessage::RevealSignature{
                    key: r,
                    signature_encrypted: enc_b,
                    signature_mac: SHA256::hmac160(&secrets.m2, &enc_b),
                })
            }
            AKEState::AwaitingRevealSignature {
                our_dh_keypair: _,
                gx_encrypted: _,
                gx_hashed: _,
            } => {
                // Ignore the message.
                Err(AKEError::MessageIgnored)
            }
            AKEState::AwaitingSignature{
                our_dh_keypair,
                key: key,
                gy: old_gy,
                secrets,
            } => {
                if old_gy != *gy {
                    // Ignore the message.
                    return Err(AKEError::MessageIgnored);
                }
                // TODO the computations below could be cached during first handling of DH Key message.
                // If this D-H Key message is the same the one you received earlier (when you entered AUTHSTATE_AWAITING_SIG):
                //    Retransmit your Reveal Signature Message.
                let pub_b: DSA::PublicKey;
                let keyid_b = 1u32;
                let m_b = SHA256::hmac(&secrets.m1, &new_encoder()
                    .write_mpi(&our_dh_keypair.public)
                    .write_mpi(gy)
                // FIXME acquire DSA public key from host, write to m_b.
                    .write_public_key(&pub_b)
                    .write_int(keyid_b)
                    .to_vec());
                // FIXME replace with actual signature calculation.
                let sig_b: Signature = [0u8;40];
                let x_b = new_encoder()
                    .write_public_key(&pub_b)
                    .write_int(keyid_b)
                    .write_signature(&sig_b)
                    .to_vec();
                let enc_b = new_encoder()
                    .write_data(&AES128::encrypt(&secrets.c, &[0u8;16], &x_b))
                    .to_vec();
                return Ok(OTRMessage::RevealSignature{
                    key: key,
                    signature_encrypted: enc_b,
                    signature_mac: SHA256::hmac160(&secrets.m2, &enc_b),
                });
            }
        };
    }

    pub fn handle_reveal_signature(
        &mut self,
        key: AES128::Key,
        signature_encrypted: Vec<u8>,
        signature_mac: MAC,
    ) -> Result<OTRMessage, AKEError> {
        return match &self.state {
            AKEState::None => {
                // Ignore the message.
                Err(AKEError::MessageIgnored)
            }
            AKEState::AwaitingDHKey { r, our_dh_keypair } => {
                // Ignore the message.
                Err(AKEError::MessageIgnored)
            }
            AKEState::AwaitingRevealSignature {
                our_dh_keypair,
                gx_encrypted,
                gx_hashed,
            } => {
                // (OTRv3) Use the received value of r to decrypt the value of gx received in the D-H Commit Message,
                // and verify the hash therein. Decrypt the encrypted signature, and verify the signature and
                // the MACs. If everything checks out:
                // - Reply with a Signature Message.
                // - Transition authstate to AUTHSTATE_NONE.
                // - Transition msgstate to MSGSTATE_ENCRYPTED.
                // - If there is a recent stored message, encrypt it and send it as a Data Message.

                // Acquire g^x from previously sent encrypted/hashed g^x-derived data and ensure authenticity.
                let gxmpi = AES128::decrypt(&key, &[0u8;16], &gx_encrypted);
                let gxmpihash = SHA256::digest(&gxmpi);
                SHA256::verify(&gxmpihash, gx_hashed)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                // Verify acquired g^x value.
                let gx = new_decoder(&gxmpi).read_mpi()
                    .or(Err(AKEError::MessageIncomplete))?;
                DH::verify_public_key(&gx)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;

                // Validate encrypted signature using MAC based on m2, ensuring signature content is unchanged.
                let secrets = our_dh_keypair.derive_secrets(&gx);
                let expected_signature_mac = SHA256::hmac160(&secrets.m2, &signature_encrypted);
                SHA256::verify(&expected_signature_mac, &signature_mac)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;

                // Acquire Bob's identity material from the encrypted x_b.
                let decoder = new_decoder(&AES128::decrypt(&secrets.c, &[0u8;16], &signature_encrypted));
                let pub_b = decoder.read_public_key().or(Err(AKEError::MessageIncomplete))?;
                let keyid_b = decoder.read_int().or(Err(AKEError::MessageIncomplete))?;
                let sig_b = decoder.read_signature().or(Err(AKEError::MessageIncomplete))?;
                // Reconstruct and verify m_b against Bob's signature, to ensure identity material is unchanged.
                let m_b_bytes = new_encoder().write_mpi(&gx).write_mpi(&our_dh_keypair.public).write_public_key(&pub_b).write_int(keyid_b).to_vec();
                let m_b = SHA256::hmac(&secrets.m1, &m_b_bytes);
                pub_b.verify(&sig_b, &m_b)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;

                self.state = AKEState::None;
                // TODO need to compute Sending/Receiving AES/MAC keys.
                // FIXME required to send OTRMessage::Signature. Put OTRMessage::Signature in the Completed? ... a little bit dirty but might be acceptable.
                return Err(AKEError::Completed);
            }
            AKEState::AwaitingSignature{
                our_dh_keypair: _,
                key: _,
                gy: _,
                secrets: _,
            } => {
                // Ignore the message.
                Err(AKEError::MessageIgnored)
            }
        };
    }

    pub fn handle_signature(
        &mut self,
        signature_encrypted: Vec<u8>,
        signature_mac: MAC,
    ) -> Result<OTRMessage, AKEError> {
        return match &self.state {
            AKEState::None => {
                // Ignore the message.
                Err(AKEError::MessageIgnored)
            }
            AKEState::AwaitingDHKey { r, our_dh_keypair } => {
                // Ignore the message.
                Err(AKEError::MessageIgnored)
            }
            AKEState::AwaitingRevealSignature {
                our_dh_keypair,
                gx_encrypted,
                gx_hashed,
            } => {
                // Ignore the message.
                Err(AKEError::MessageIgnored)
            }
            AKEState::AwaitingSignature{
                our_dh_keypair: _,
                key: _,
                gy: _,
                secrets: _,
            } => {
                // Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:
                // - Transition authstate to AUTHSTATE_NONE.
                // - Transition msgstate to MSGSTATE_ENCRYPTED.
                // - If there is a recent stored message, encrypt it and send it as a Data Message.
            }
        };
    }
}

pub enum AKEError {
    CryptographicViolation(CryptoError),
    MessageIgnored,
    MessageIncomplete,
    Completed,
}