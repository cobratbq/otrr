use std::rc::Rc;

use crate::{
    crypto::{constant, CryptoError, AES128, DH, DSA, OTR::AKESecrets, SHA256},
    encoding::{
        DHCommitMessage, DHKeyMessage, EncodedMessageType, OTRDecoder, OTREncoder,
        RevealSignatureMessage, SignatureMessage, SSID,
    },
    Host, Version,
};
use num_bigint::BigUint;

pub struct AKEContext {
    version: Version,
    host: Rc<dyn Host>,
    state: AKEState,
}

impl AKEContext {
    pub fn new(host: Rc<dyn Host>) -> Self {
        Self {
            version: Version::V3,
            host,
            state: AKEState::None,
        }
    }

    pub fn version(&self) -> Version {
        self.version.clone()
    }

    pub fn initiate(&mut self) -> EncodedMessageType {
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
        EncodedMessageType::DHCommit(DHCommitMessage {
            gx_encrypted,
            gx_hashed,
        })
    }

    /// `transfer` transfers our `AKEContext` specifically for the case that a DH-Key response
    /// arrives and the DH-Commit message was sent with reciever-tag ZERO. (An edge case that is
    /// allowed as we do not yet know the receiver instance tag of the other client.) Therefore, we
    /// only allow transferring the state if the state corresponds: `AKEState::AwaitingDHKey`.
    pub fn transfer(&self) -> Result<AKEContext, AKEError> {
        match &self.state {
            AKEState::AwaitingDHKey(state) => Ok(Self {
                version: self.version.clone(),
                host: Rc::clone(&self.host),
                state: AKEState::AwaitingDHKey(AwaitingDHKey {
                    our_dh_keypair: state.our_dh_keypair.clone(),
                    r: state.r.clone(),
                }),
            }),
            AKEState::None
            | AKEState::AwaitingRevealSignature(_)
            | AKEState::AwaitingSignature(_) => Err(AKEError::IncorrectState),
        }
    }

    pub fn handle_dhcommit(
        &mut self,
        msg: DHCommitMessage,
    ) -> Result<EncodedMessageType, AKEError> {
        let (result, transition) = match &self.state {
            AKEState::None => Self::handle_dhcommit_from_initial(msg),
            AKEState::AwaitingDHKey(state) => {
                // This is the trickiest transition in the whole protocol. It indicates that you
                // have already sent a D-H Commit message to your correspondent, but that he either
                // didn't receive it, or just didn't receive it yet, and has sent you one as well.
                // The symmetry will be broken by comparing the hashed gx you sent in your
                // D-H Commit Message with the one you received, considered as 32-byte unsigned
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
                    let dhcommit = EncodedMessageType::DHCommit(DHCommitMessage {
                        gx_encrypted: our_gx_encrypted,
                        gx_hashed: Vec::from(our_gxmpi_hashed),
                    });
                    (Ok(dhcommit), None)
                } else {
                    // Forget your old gx value that you sent (encrypted) earlier, and pretend you
                    // are in AUTHSTATE_NONE; i.e. reply with a D-H Key Message, and transition
                    // authstate to AUTHSTATE_AWAITING_REVEALSIG.
                    Self::handle_dhcommit_from_initial(msg)
                }
            }
            AKEState::AwaitingRevealSignature(state) => {
                // Retransmit your D-H Key Message (the same one as you sent when you entered
                // AUTHSTATE_AWAITING_REVEALSIG). Forget the old D-H Commit message, and use this
                // new one instead.
                // There are a number of reasons this might happen, including:
                // - Your correspondent simply started a new AKE.
                // - Your correspondent resent his D-H Commit message, as specified above.
                // - On some networks, like AIM, if your correspondent is logged in multiple times,
                //   each of his clients will send a D-H Commit Message in response to a
                //   Query Message; resending the same D-H Key Message in response to each of those
                //   messages will prevent compounded confusion, since each of his clients will see
                //   each of the D-H Key Messages you send. [And the problem gets even worse if you
                //   are each logged in multiple times.]
                let dhkey = EncodedMessageType::DHKey(DHKeyMessage {
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
                // Reply with a new D-H Key message, and transition authstate to
                // AUTHSTATE_AWAITING_REVEALSIG.
                let our_dh_keypair = DH::Keypair::generate();
                let dhkey = EncodedMessageType::DHKey(DHKeyMessage {
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
        msg: DHCommitMessage,
    ) -> (Result<EncodedMessageType, AKEError>, Option<AKEState>) {
        // Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
        let keypair = DH::Keypair::generate();
        let dhkey = EncodedMessageType::DHKey(DHKeyMessage {
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

    pub fn handle_dhkey(&mut self, msg: DHKeyMessage) -> Result<EncodedMessageType, AKEError> {
        let (result, transition) = match &self.state {
            AKEState::None | AKEState::AwaitingRevealSignature(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingDHKey(state) => {
                DH::verify_public_key(&msg.gy).map_err(AKEError::CryptographicViolation)?;
                // Reply with a Reveal Signature Message and transition authstate to
                // `AUTHSTATE_AWAITING_SIG`.
                let s = state.our_dh_keypair.generate_shared_secret(&msg.gy);
                let secrets = AKESecrets::derive(&OTREncoder::new().write_mpi(&s).to_vec());
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
                // "This is the signature, using the private part of the key pubB, of the 32-byte MB
                //  (taken modulo q instead of being truncated (as described in FIPS-186), and not
                //  hashed again)."
                let sig_b = dsa_keypair.sign(&m_b);
                let x_b = OTREncoder::new()
                    .write_public_key(&pub_b)
                    .write_int(keyid_b)
                    .write_signature(&sig_b)
                    .to_vec();
                let enc_b = OTREncoder::new()
                    .write_data(&secrets.c.encrypt(&[0u8; 16], &x_b))
                    .to_vec();
                let mac_enc_b = SHA256::hmac160(&secrets.m2, &enc_b);
                let reveal_sig_message = RevealSignatureMessage {
                    key: state.r.clone(),
                    signature_encrypted: enc_b,
                    signature_mac: mac_enc_b,
                };
                (
                    Ok(EncodedMessageType::RevealSignature(
                        reveal_sig_message.clone(),
                    )),
                    Some(AKEState::AwaitingSignature(AwaitingSignature {
                        our_dh_keypair: Rc::clone(&state.our_dh_keypair),
                        gy: msg.gy,
                        s,
                        previous_message: reveal_sig_message,
                    })),
                )
            }
            AKEState::AwaitingSignature(state) => {
                if state.gy != msg.gy {
                    // Ignore the message.
                    return Err(AKEError::MessageIgnored);
                }
                (
                    Ok(EncodedMessageType::RevealSignature(
                        state.previous_message.clone(),
                    )),
                    None,
                )
            }
        };
        if transition.is_some() {
            self.state = transition.unwrap();
        }
        result
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_reveal_signature(
        &mut self,
        msg: RevealSignatureMessage,
    ) -> Result<(CryptographicMaterial, EncodedMessageType), AKEError> {
        let (result, transition) = match &self.state {
            AKEState::None | AKEState::AwaitingDHKey(_) | AKEState::AwaitingSignature(_) => {
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
                constant::verify(&gxmpihash, &state.gx_hashed)
                    .map_err(AKEError::CryptographicViolation)?;
                // Verify acquired g^x value.
                let gx = OTRDecoder::new(&gxmpi)
                    .read_mpi()
                    .or(Err(AKEError::MessageIncomplete))?;
                DH::verify_public_key(&gx).map_err(AKEError::CryptographicViolation)?;

                // Validate encrypted signature using MAC based on m2, ensuring signature content is unchanged.
                let s = state.our_dh_keypair.generate_shared_secret(&gx);
                let secrets = AKESecrets::derive(&OTREncoder::new().write_mpi(&s).to_vec());
                let expected_signature_mac = SHA256::hmac160(
                    &secrets.m2,
                    &OTREncoder::new()
                        .write_data(&msg.signature_encrypted)
                        .to_vec(),
                );
                constant::verify(&expected_signature_mac, &msg.signature_mac)
                    .map_err(AKEError::CryptographicViolation)?;

                // Acquire Bob's identity material from the encrypted x_b.
                let x_b = secrets.c.decrypt(&[0u8; 16], &msg.signature_encrypted);
                let mut decoder = OTRDecoder::new(&x_b);
                let pub_b = decoder
                    .read_public_key()
                    .or(Err(AKEError::MessageIncomplete))?;
                let keyid_b = decoder.read_int().or(Err(AKEError::MessageIncomplete))?;
                assert_ne!(0, keyid_b);
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
                    .map_err(AKEError::CryptographicViolation)?;

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
                let sig_m_a = keypair.sign(&m_a);
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
                            version: self.version.clone(),
                            ssid: secrets.ssid,
                            our_dh: (*state.our_dh_keypair).clone(),
                            their_dh: gx,
                            their_dsa: pub_b,
                        },
                        EncodedMessageType::Signature(SignatureMessage {
                            signature_encrypted: encrypted_signature,
                            signature_mac: encrypted_mac,
                        }),
                    )),
                    AKEState::None,
                )
            }
        };
        self.state = transition;
        result
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn handle_signature(
        &mut self,
        msg: SignatureMessage,
    ) -> Result<CryptographicMaterial, AKEError> {
        let (result, transition) = match &self.state {
            AKEState::None | AKEState::AwaitingDHKey(_) | AKEState::AwaitingRevealSignature(_) => {
                // Ignore the message.
                return Err(AKEError::MessageIgnored);
            }
            AKEState::AwaitingSignature(state) => {
                // Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:
                // - Transition authstate to AUTHSTATE_NONE.
                // - Transition msgstate to MSGSTATE_ENCRYPTED.
                // - If there is a recent stored message, encrypt it and send it as a Data Message.
                let secrets = AKESecrets::derive(&OTREncoder::new().write_mpi(&state.s).to_vec());
                let mac = SHA256::hmac160(
                    &secrets.m2p,
                    &OTREncoder::new()
                        .write_data(&msg.signature_encrypted)
                        .to_vec(),
                );
                constant::verify(&msg.signature_mac, &mac)
                    .map_err(AKEError::CryptographicViolation)?;
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
                assert_ne!(0, keyid_a);
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
                    .map_err(AKEError::CryptographicViolation)?;
                (
                    Ok(CryptographicMaterial {
                        version: self.version.clone(),
                        ssid: secrets.ssid,
                        our_dh: (*state.our_dh_keypair).clone(),
                        their_dh: state.gy.clone(),
                        their_dsa: pub_a,
                    }),
                    AKEState::None,
                )
            }
        };
        self.state = transition;
        result
    }
}

/// `CryptographicMaterial` contains the cryptographic material acquired during the AKE.
///
/// The AKE always uses keyid 1 for both parties, so no point in including these.
// TODO something about highlighting certain part of ssid if comparing values, so need to double-check.
pub struct CryptographicMaterial {
    pub version: Version,
    pub ssid: SSID,
    pub our_dh: DH::Keypair,
    pub their_dh: BigUint,
    pub their_dsa: DSA::PublicKey,
}

/// `AKEState` represents available/recognized AKE states.
enum AKEState {
    /// None indicates no AKE is in progress. Tuple contains predominant verification status for most recent previous execution.
    None,
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
    gy: BigUint,
    s: DH::SharedSecret,
    previous_message: RevealSignatureMessage,
}

/// `AKEError` contains the variants of errors produced during AKE.
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
    // Incorrect AKE state for message to be handled.
    IncorrectState,
}
