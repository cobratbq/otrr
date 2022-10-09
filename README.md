# otrr

OTR version 3 implementation in Rust.

__status__ work-in-progress, "_It builds, usually._"

Tests demonstrate an established OTR session, however this only proves that bugs are symmetric in nature.

## Warning

- crate `dsa`: disclaimer states it is not thoroughly verified

## Architecture

- OTRv3 only (OTRv2 and earlier are not supported)
- Structured for security:
  - security-sensitive primitives in separate module (`crypto`)
  - strictly separated states resulting in strictly separated secrets
- __not__ multi-threaded

## Design

`TODO write design considerations here`

## Under consideration

- Persistence for known public keys, previously verified identities (SMP), etc.

<details>
  <summary>Checklist</summary>

> ☐: feature, ☑: implemented, ✔: verified

__Functionality__:

- ☑ Normal messages:
  - ☑ Plaintext message
  - ☑ Whitespace-tagged message
  - ☑ Query message
  - ☑ Error message
- ☑ Authenticated Key Exchange (AKE)
- ☑ Socialist Millionaire's Protocol (SMP)
  - ☑ SMP zero-knowledge secret verificaton (w/ or w/o user-provided question)
  - ☐ Manual verification (SSID)
- ☑ DSA signatures
- ☑ Encryption
- ☑ OTR-encoding
  - ☑ Reading
  - ☑ Writing
- ☐ Policies:
  - ☑ `REQUIRE_ENCRYPTION` take appropriate actions given that active policy requires encryption.
  - ☑ `WHITESPACE_START_AKE` automatically initiate AKE when whitespace tag is received.
  - ☑ `ERROR_START_AKE` initiate AKE upon receiving error message.
  - ☐ ability to change policy for account or individual instance (during use).
- ☑ Fragmentation:
  - ☑ Assemble fragments of incoming message.
  - ☑ Fragment outgoing messages.
- ☐ Heartbeat-messages: keep session alive and ensure regular key rotation.
- ☐ Store plaintext message for transmission under right circumstances (i.e. `REQUIRE_ENCRYPTION` policy, in-progress AKE, etc.)
- ☐ Expose the Extra Symmetric Key (TLV type `8`)

__Operational__:

- ☑ Single instance of `Account` represents single account on a chat network: allows for specific identity (_DSA keypair_), chat network/transport.
- ☐ Thread-safety. (Not yet determined necessary.)  
    _Limited by ordering-requirement for transport. Expect processing single message at a time._

__Developmental__:

- ☑ No logic for managing multiple accounts:  
  _We keep this separated and up to the client to implement if necessary. Essentially, just tying the `Account` to the corresponding chat account logic is sufficient, and any management on top of that risks prescribing a certain structure for the host application (e.g. chat application)._
- ☐ API for managing multiple accounts, keys, policies?
- ☐ Unit tests: too few tests, because rust syntax is that expressive

__Known issues__:

- How to deal with multiple instances, "default instance", "selected/active instance"? Especially when dealing with incidental reception of plaintext messages while encrypted session is established for some instance.
- The OTR specification documents that any message payload is in UTF-8 and _may contain_ HTML. However, this makes it ambiguous for how the content should be interpreted and results and risks may very per chat network.
- There is no convention on how the Extra Symmetric Key should be used.
- ..
</details>
