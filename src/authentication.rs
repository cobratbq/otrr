use std::rc::Rc;

use crate::{
    crypto::{
        CryptoError, AES128,
        DH::{self},
        OTR::DerivedSecrets,
        SHA256,
    },
    encoding::{
        DHCommitMessage, DHKeyMessage, OTRDecoder, OTREncoder, OTRMessageType,
        RevealSignatureMessage, SignatureMessage, SSID,
    },
    host::Host,
    Version,
};
use num_bigint::BigUint;

pub struct AKEContext {
    host: Rc<dyn Host>,
    state: AKEState,
}

// FIXME check verification of public keys everywhere.
// FIXME check updating of state everywhere where necessary.
// FIXME there was a need to cut off 0x00 from head somewhere. I believe in DSA public key serialized.
impl AKEContext {
    pub fn new(host: Rc<dyn Host>) -> Self {
        Self {
            host: host,
            state: AKEState::None(VerificationState::UNKNOWN),
        }
    }

    pub fn is_verified(&self) -> bool {
        if let AKEState::None(VerificationState::VERIFIED) = self.state {
            true
        } else {
            false
        }
    }

    pub fn initiate(&mut self) -> Result<OTRMessageType, AKEError> {
        let keypair = DH::Keypair::generate();
        let r = AES128::Key::generate();
        let gxmpi = OTREncoder::new().write_mpi(&keypair.public).to_vec();
        let gx_encrypted = OTREncoder::new()
            .write_data(&r.encrypt(&[0; 16], &gxmpi))
            .to_vec();
        let gx_hashed = SHA256::digest(&gxmpi).to_vec();
        // Send D-H Commit message and await D-H Key message.
        self.state = AKEState::AwaitingDHKey(AwaitingDHKey {
            our_dh_keypair: Rc::new(keypair),
            r,
        });
        Ok(OTRMessageType::DHCommit(DHCommitMessage {
            gx_encrypted,
            gx_hashed,
        }))
    }

    pub fn handle_dhcommit(&mut self, msg: DHCommitMessage) -> Result<OTRMessageType, AKEError> {
        let (result, transition) = match &self.state {
            AKEState::None(_) => self.handle_dhcommit_from_initial(msg),
            AKEState::AwaitingDHKey(state) => {
                // This is the trickiest transition in the whole protocol. It indicates that you have already sent a
                // D-H Commit message to your correspondent, but that he either didn't receive it, or just didn't
                // receive it yet, and has sent you one as well. The symmetry will be broken by comparing the hashed gx
                // you sent in your D-H Commit Message with the one you received, considered as 32-byte unsigned
                // big-endian values.
                let gxmpi = OTREncoder::new()
                    .write_mpi(&state.our_dh_keypair.public)
                    .to_vec();
                let our_gxmpi_hashed = SHA256::digest(&gxmpi);
                let our_hash = BigUint::from_bytes_be(&our_gxmpi_hashed);
                let their_hash = BigUint::from_bytes_be(&msg.gx_hashed);
                if our_hash > their_hash {
                    // Ignore the incoming D-H Commit message, but resend your D-H Commit message.
                    let our_gx_encrypted = state.r.encrypt(&[0u8; 16], &gxmpi);
                    let dhcommit = OTRMessageType::DHCommit(DHCommitMessage {
                        gx_encrypted: our_gx_encrypted,
                        gx_hashed: Vec::from(our_gxmpi_hashed),
                    });
                    (Ok(dhcommit), None)
                } else {
                    // Forget your old gx value that you sent (encrypted) earlier, and pretend you're in
                    // AUTHSTATE_NONE; i.e. reply with a D-H Key Message, and transition authstate to
                    // AUTHSTATE_AWAITING_REVEALSIG.
                    self.handle_dhcommit_from_initial(msg)
                }
            }
            AKEState::AwaitingRevealSignature(state) => {
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
                let dhkey = OTRMessageType::DHKey(DHKeyMessage {
                    gy: state.our_dh_keypair.public.clone(),
                });
                (
                    Ok(dhkey),
                    Some(AKEState::AwaitingRevealSignature(AwaitingRevealSignature {
                        our_dh_keypair: Rc::clone(&state.our_dh_keypair),
                        gx_encrypted: state.gx_encrypted.clone(),
                        gx_hashed: state.gx_hashed.clone(),
                    })),
                )
            }
            AKEState::AwaitingSignature(_) => {
                // Reply with a new D-H Key message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
                let our_dh_keypair = DH::Keypair::generate();
                let dhkey = OTRMessageType::DHKey(DHKeyMessage {
                    gy: our_dh_keypair.public.clone(),
                });
                let gx_encrypted = msg.gx_encrypted;
                let gx_hashed = msg.gx_hashed;
                (
                    Ok(dhkey),
                    Some(AKEState::AwaitingRevealSignature(AwaitingRevealSignature {
                        our_dh_keypair: Rc::new(our_dh_keypair),
                        gx_encrypted,
                        gx_hashed,
                    })),
                )
            }
        };
        if transition.is_some() {
            self.state = transition.unwrap();
        }
        result
    }

    fn handle_dhcommit_from_initial(
        &self,
        msg: DHCommitMessage,
    ) -> (Result<OTRMessageType, AKEError>, Option<AKEState>) {
        // Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
        let keypair = DH::Keypair::generate();
        let dhkey = OTRMessageType::DHKey(DHKeyMessage {
            gy: keypair.public.clone(),
        });
        let gx_encrypted = msg.gx_encrypted;
        let gx_hashed = msg.gx_hashed;
        (
            Ok(dhkey),
            Some(AKEState::AwaitingRevealSignature(AwaitingRevealSignature {
                our_dh_keypair: Rc::new(keypair),
                gx_encrypted,
                gx_hashed,
            })),
        )
    }

    pub fn handle_dhkey(&mut self, msg: DHKeyMessage) -> Result<OTRMessageType, AKEError> {
        let (result, transition) = match &self.state {
            AKEState::None(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingDHKey(state) => {
                DH::verify_public_key(&msg.gy)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                // Reply with a Reveal Signature Message and transition authstate to AUTHSTATE_AWAITING_SIG.
                let s = state.our_dh_keypair.generate_shared_secret(&msg.gy);
                let secrets =
                    DerivedSecrets::derive_secrets(&OTREncoder::new().write_mpi(&s).to_vec());
                // TODO consider random starting key-id for initial key-id. (Spec: keyid > 0)
                // FIXME ensure keypair is only acquired once per AKE conversation (sequence).
                let dsa_keypair = self.host.keypair();
                let pub_b = dsa_keypair.public_key();
                let keyid_b = 1u32;
                let m_b = SHA256::hmac(
                    &secrets.m1,
                    &OTREncoder::new()
                        .write_mpi(&state.our_dh_keypair.public)
                        .write_mpi(&msg.gy)
                        .write_public_key(&pub_b)
                        .write_int(keyid_b)
                        .to_vec(),
                );
                let sig_b = dsa_keypair
                    .sign(&m_b)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                let x_b = OTREncoder::new()
                    .write_public_key(&pub_b)
                    .write_int(keyid_b)
                    .write_signature(&sig_b)
                    .to_vec();
                let enc_b = OTREncoder::new()
                    .write_data(&secrets.c.encrypt(&[0u8; 16], &x_b))
                    .to_vec();
                let mac_enc_b = SHA256::hmac160(&secrets.m2, &enc_b);
                (
                    Ok(OTRMessageType::RevealSignature(RevealSignatureMessage {
                        key: state.r.clone(),
                        signature_encrypted: enc_b,
                        signature_mac: mac_enc_b,
                    })),
                    Some(AKEState::AwaitingSignature(AwaitingSignature {
                        our_dh_keypair: Rc::clone(&state.our_dh_keypair),
                        gy: msg.gy.clone(),
                        key: state.r.clone(),
                        s: s,
                    })),
                )
            }
            AKEState::AwaitingRevealSignature(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingSignature(state) => {
                if state.gy != msg.gy {
                    // Ignore the message.
                    return Err(AKEError::MessageIgnored);
                }
                let secrets =
                    DerivedSecrets::derive_secrets(&OTREncoder::new().write_mpi(&state.s).to_vec());
                // TODO the computations below could be cached during first handling of DH Key message.
                // If this D-H Key message is the same the one you received earlier (when you entered AUTHSTATE_AWAITING_SIG):
                //    Retransmit your Reveal Signature Message.
                let dsa_keypair = self.host.keypair();
                let pub_b = dsa_keypair.public_key();
                let keyid_b = 1u32;
                let m_b = SHA256::hmac(
                    &secrets.m1,
                    &OTREncoder::new()
                        .write_mpi(&state.our_dh_keypair.public)
                        .write_mpi(&msg.gy)
                        // FIXME acquire DSA public key from host, write to m_b.
                        .write_public_key(&pub_b)
                        .write_int(keyid_b)
                        .to_vec(),
                );
                // FIXME replace with actual signature calculation. (appropriate format/input for signature (mod q))
                let sig_b = dsa_keypair
                    .sign(&m_b)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                let x_b = OTREncoder::new()
                    .write_public_key(&pub_b)
                    .write_int(keyid_b)
                    .write_signature(&sig_b)
                    .to_vec();
                let enc_b = OTREncoder::new()
                    .write_data(&secrets.c.encrypt(&[0u8; 16], &x_b))
                    .to_vec();
                let mac_enc_b = SHA256::hmac160(&secrets.m2, &enc_b);
                (
                    Ok(OTRMessageType::RevealSignature(RevealSignatureMessage {
                        key: state.key.clone(),
                        signature_encrypted: enc_b,
                        signature_mac: mac_enc_b,
                    })),
                    None,
                )
            }
        };
        if transition.is_some() {
            self.state = transition.unwrap();
        }
        result
    }

    pub fn handle_reveal_signature(
        &mut self,
        msg: RevealSignatureMessage,
    ) -> Result<(CryptographicMaterial, OTRMessageType), AKEError> {
        let (result, transition) = match &self.state {
            AKEState::None(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingDHKey(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingSignature(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingRevealSignature(state) => {
                // (OTRv3) Use the received value of r to decrypt the value of gx received in the D-H Commit Message,
                // and verify the hash therein. Decrypt the encrypted signature, and verify the signature and
                // the MACs. If everything checks out:
                // - Reply with a Signature Message.
                // - Transition authstate to AUTHSTATE_NONE.
                // - Transition msgstate to MSGSTATE_ENCRYPTED.
                // - If there is a recent stored message, encrypt it and send it as a Data Message.

                // Acquire g^x from previously sent encrypted/hashed g^x-derived data and ensure authenticity.
                let gxmpi = msg.key.decrypt(&[0u8; 16], &state.gx_encrypted);
                let gxmpihash = SHA256::digest(&gxmpi);
                SHA256::verify(&gxmpihash, &state.gx_hashed)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                // Verify acquired g^x value.
                let gx = OTRDecoder::new(&gxmpi)
                    .read_mpi()
                    .or(Err(AKEError::MessageIncomplete))?;
                DH::verify_public_key(&gx)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;

                // Validate encrypted signature using MAC based on m2, ensuring signature content is unchanged.
                let s = state.our_dh_keypair.generate_shared_secret(&gx);
                let secrets =
                    DerivedSecrets::derive_secrets(&OTREncoder::new().write_mpi(&s).to_vec());
                let expected_signature_mac = SHA256::hmac160(
                    &secrets.m2,
                    &OTREncoder::new()
                        .write_data(&msg.signature_encrypted)
                        .to_vec(),
                );
                SHA256::verify(&expected_signature_mac, &msg.signature_mac)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;

                // Acquire Bob's identity material from the encrypted x_b.
                let x_b = secrets.c.decrypt(&[0u8; 16], &msg.signature_encrypted);
                let mut decoder = OTRDecoder::new(&x_b);
                let pub_b = decoder
                    .read_public_key()
                    .or(Err(AKEError::MessageIncomplete))?;
                let keyid_b = decoder.read_int().or(Err(AKEError::MessageIncomplete))?;
                // FIXME sig_b is not used, there should be a verification step for this!
                let sig_b = decoder
                    .read_signature()
                    .or(Err(AKEError::MessageIncomplete))?;
                // Reconstruct and verify m_b against Bob's signature, to ensure identity material is unchanged.
                let m_b_bytes = OTREncoder::new()
                    .write_mpi(&gx)
                    .write_mpi(&state.our_dh_keypair.public)
                    .write_public_key(&pub_b)
                    .write_int(keyid_b)
                    .to_vec();
                let m_b = SHA256::hmac(&secrets.m1, &m_b_bytes);
                pub_b
                    .verify(&sig_b, &m_b)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;

                let keyid_a = 1u32;
                let keypair = self.host.keypair();
                let m_a = SHA256::hmac(
                    &secrets.m1p,
                    &OTREncoder::new()
                        .write_mpi(&state.our_dh_keypair.public)
                        .write_mpi(&gx)
                        .write_public_key(&keypair.public_key())
                        .write_int(keyid_a)
                        .to_vec(),
                );
                let sig_m_a = keypair
                    .sign(&m_a)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                let x_a = OTREncoder::new()
                    .write_public_key(&keypair.public_key())
                    .write_int(keyid_a)
                    .write_signature(&sig_m_a)
                    .to_vec();
                let encrypted_signature = secrets.cp.encrypt(&[0u8; 16], &x_a);
                let encrypted_mac = SHA256::hmac160(
                    &secrets.m2p,
                    &OTREncoder::new().write_data(&encrypted_signature).to_vec(),
                );
                (
                    Ok((
                        CryptographicMaterial {
                            version: Version::V3,
                            ssid: secrets.ssid,
                            our_dh: (*state.our_dh_keypair).clone(),
                            their_dh: gx,
                        },
                        OTRMessageType::Signature(SignatureMessage {
                            signature_encrypted: encrypted_signature,
                            signature_mac: encrypted_mac,
                        }),
                    )),
                    AKEState::None(VerificationState::VERIFIED),
                )
            }
        };
        self.state = transition;
        result
    }

    pub fn handle_signature(
        &mut self,
        msg: SignatureMessage,
    ) -> Result<CryptographicMaterial, AKEError> {
        let (result, transition) = match &self.state {
            AKEState::None(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingDHKey(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingRevealSignature(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingSignature(state) => {
                // Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:
                // - Transition authstate to AUTHSTATE_NONE.
                // - Transition msgstate to MSGSTATE_ENCRYPTED.
                // - If there is a recent stored message, encrypt it and send it as a Data Message.
                let secrets =
                    DerivedSecrets::derive_secrets(&OTREncoder::new().write_mpi(&state.s).to_vec());
                let mac = SHA256::hmac160(
                    &secrets.m2p,
                    &OTREncoder::new()
                        .write_data(&msg.signature_encrypted)
                        .to_vec(),
                );
                SHA256::verify(&msg.signature_mac, &mac)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                let x_a = secrets.cp.decrypt(
                    &[0u8; 16],
                    &OTRDecoder::new(&msg.signature_encrypted)
                        .read_data()
                        .or(Err(AKEError::MessageIncomplete))?,
                );
                let mut decoder = OTRDecoder::new(&x_a);
                let pub_a = decoder
                    .read_public_key()
                    .or(Err(AKEError::MessageIncomplete))?;
                let keyid_a = decoder.read_int().or(Err(AKEError::MessageIncomplete))?;
                let sig_m_a = decoder
                    .read_signature()
                    .or(Err(AKEError::MessageIncomplete))?;
                let m_a = SHA256::hmac(
                    &secrets.m1p,
                    &OTREncoder::new()
                        .write_mpi(&state.gy)
                        .write_mpi(&state.our_dh_keypair.public)
                        .write_public_key(&pub_a)
                        .write_int(keyid_a)
                        .to_vec(),
                );
                pub_a
                    .verify(&sig_m_a, &m_a)
                    .or_else(|err| Err(AKEError::CryptographicViolation(err)))?;
                (
                    Ok(CryptographicMaterial {
                        version: Version::V3,
                        ssid: secrets.ssid,
                        our_dh: (*state.our_dh_keypair).clone(),
                        their_dh: state.gy.clone(),
                    }),
                    AKEState::None(VerificationState::VERIFIED),
                )
            }
        };
        self.state = transition;
        result
    }
}

/// CryptographicMaterial contains the cryptographic material acquired during the AKE.
///
/// The AKE always uses keyid 1 for both parties, so no point in including these.
// TODO something about highlighting certain part of ssid if comparing values, so need to double-check.
pub struct CryptographicMaterial {
    pub version: Version,
    pub ssid: SSID,
    // FIXME can we do without the reference-counting so that we know absolutely sure that this is the only instance?
    pub our_dh: DH::Keypair,
    pub their_dh: BigUint,
}

/// AKEState represents available/recognized AKE states.
enum AKEState {
    /// None indicates no AKE is in progress. Tuple contains predominant verification status for most recent previous execution.
    None(VerificationState),
    /// AwaitingDHKey state contains data as present/needed upon transitioning to this state.
    AwaitingDHKey(AwaitingDHKey),
    /// AwaitingRevealSignature state contains data up to transitioning to this state.
    AwaitingRevealSignature(AwaitingRevealSignature),
    /// AwaitingSignature contains data up to transitioning to this state.
    AwaitingSignature(AwaitingSignature),
}

struct AwaitingDHKey {
    r: AES128::Key,
    our_dh_keypair: Rc<DH::Keypair>,
}

struct AwaitingRevealSignature {
    our_dh_keypair: Rc<DH::Keypair>,
    gx_encrypted: Vec<u8>,
    gx_hashed: Vec<u8>,
}

// TODO: clean-up fields, now gy, s and secrets.
struct AwaitingSignature {
    our_dh_keypair: Rc<DH::Keypair>,
    key: AES128::Key,
    gy: BigUint,
    s: DH::SharedSecret,
}

/// VerificationState represents the various states of verification.
enum VerificationState {
    // FIXME should we ever transition back to UNKNOWN on failure during AKE?
    /// Unknown represents the verification status where we are not aware of a previous successful verification.
    UNKNOWN,
    /// Verified indicates that the previous authentication process completed successfully.
    VERIFIED,
}

/// AKEError contains the variants of errors produced during AKE.
#[derive(std::fmt::Debug)]
pub enum AKEError {
    /// AKE message processing produced an error due to a cryptographic violation.
    CryptographicViolation(CryptoError),
    /// AKE message ignored due to it arriving in violation of protocol.
    MessageIgnored,
    /// AKE message is incomplete. Errors were encountered while reading out message components.
    MessageIncomplete,
    /// AKE completed and no response message is produced/necessary.
    Completed,
}
