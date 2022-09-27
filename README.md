# otrr

OTR version 3 implementation in Rust.

__status__ "_It builds, usually._"

__warning__ this is a work-in-progress with current focus being the functional implementation of a design that takes security into account.

## Warning

- crate `dsa`: disclaimer states it is not thoroughly verified

## Architecture

- OTRv3 only (OTRv2 and earlier are not supported)
- Structured for security:
  - security-sensitive primitives in separate module (`crypto`)
  - strictly separated states resulting in strictly separated secrets
- __not__ multi-threaded

## Design

- Authenticated Key Exchange (AKE)
- Signatures for long-term identity
- Encrypted exchange of messages
- Socialist Millionaire's Protocol (SMP)
- Fragmentation

## Under consideration

- Persistence for known public keys, previously verified identities (SMP), etc.

<details>
  <summary>Checklist</summary>

> ☐: feature, ☑: implemented, ✔: verified

__Functionality__:

- ☑ Normal messages:
  - ☑ Plaintext message
  - ☐ Whitespace-tagged message
  - ☑ Query message
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
  - ☐ ability to change policy for account during use.
- ☑ Fragmentation:
  - ☑ Assemble fragments of incoming message.
  - ☐ Fragment outgoing messages.
- ☐ Optional: (only fleetingly described)
  - ☐ Heartbeat-messages: keep session alive and ensure regular key rotation.
  - ☐ Store plaintext message for transmission under right circumstances (i.e. `REQUIRE_ENCRYPTION` policy, in-progress AKE, etc.)
- ☐ Expose the Extra Symmetric Key (TLV type `8`)

__Operational__:

- ☑ Single instance of `Account` represents single account on a chat network: allows for specific identity (_DSA keypair_), chat network/transport.
- ☐ Thread-safety. (Not yet determined necessary.)  
    _Limited by ordering-requirement for transport. Expect processing single message at a time._

__Developmental__:

- ☑ No logic for managing multiple accounts:  
  _We keep this separated and up to the client to implement if necessary. Essentially, just tying the `Session` to the corresponding chat account logic is sufficient, and any management on top of that risks prescribing a certain structure for the host application (e.g. chat application)._
- ☐ Errors do not propagate too far s.t. details leak to the client.
- ☐ Threading design choices and in-logic callbacks (into client) are not too restricting (i.e. cause problems)
- ☐ Need thread-safety for top-level API?
- ☐ API and logic for managing multiple accounts, keys, policies.
- ☐ ..

__Known issues__:

- How to deal with multiple instances, "default instance", "selected/active instance"? Especially when dealing with incidental reception of plaintext messages while encrypted session is established for some instance.
- The OTR specification documents that any message payload is in UTF-8 and _may contain_ HTML. However, this makes it ambiguous for how the content should be interpreted and results and risks may very per chat network.
- There is no convention on how the Extra Symmetric Key should be used.
- ..
</details>

### notes

- `Session` <---[1-*]---> `Instance`, with:
  - `Session` expected to do preselection of protocol aspects (version, anything else) and other decisions prior to delegating to the designated `Instance`.
  - `Instance` dedicated processing for a specific configuration of version, receiver tag, etc.
