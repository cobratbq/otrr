# otrr

OTR in rust.

__status__ work-in-progress, [OTRv4] functional, tested against [otr4j], further fine-tuning likely when gaining adoption.

An (minimal) "example" client is available at [echonetwork], which is used for interoperability testing with [otr4j].

## Goals

- [OTRv4] + [OTR 3][OTR3] (OTRv2 and earlier are not supported)  
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
  _This is somewhat controversial due to risk of sending queued messages to wrong established session._
- ☐ Expose the Extra Symmetric Key (TLV type `8` in OTR3, TLV type `7` in OTRv4)
- ☑ Session expiration  
  _Session expiration is provided only as a method-call. This is currently an action that the host (chat-application) must perform._
- ☑ [OTR 3][OTR3]:
  - ☑ Instance-tags (distinguish multiple clients for the same account)
  - ☑ Fragmentation with instance-tags.
- ☑ [OTRv4]:
  - ☑ Upgraded cryptographic primitives, DAKE, Double-Ratchet, mixed ephemeral keys
  - ☑ Client-profiles
  - ☑ Fragmentation with identifier
  - ☑ FIXME continue itemizing and include incomplete parts ...
  - ☐ Out-of-order message-keys:
    - ☑ messages in order,
    - ☑ skipping messages,
    - ☐ message-keys from skipped keys store, i.e. out-of-order reception

__Operational__:

- ☑ Single instance of `Account` represents single account on a chat network: allows for specific identity (_DSA keypair_), chat network/transport.
- ☐ Thread-safety. (Not yet determined necessary.)  
  _Given that most messages can be processed one at a time, most benefit is derived from having separate tasks for session expiration and heartbeats. However, these may be interleaved with message processing._

__Developmental__:

- ☑ No logic for managing multiple accounts:  
  _We keep this separated and up to the client to implement as necessary. Essentially, just tying the `Account` to the corresponding chat account logic is sufficient, and additional management risks prescribing a certain structure to the host application (e.g. chat application)._
- ☐ API for managing multiple accounts, keys, policies?
- ☐ Unit tests: too few tests, even though rust syntax is that expressive.
- ☐ Resilient to faulty implementations of `Host` as provided by the client.  
    _At this moment it is not clear how to do this: `std::panic::catch_unwind` is not guaranteed to catch and handle all panics._

__Known issues__:

- How to deal with multiple instances, "default instance", "selected/active instance"? Especially when dealing with incidental reception of plaintext messages while encrypted session is established for some instance.
- The OTR specification documents that any message payload is in UTF-8 and _may contain_ HTML. However, this makes it ambiguous for how the content should be interpreted and results and risks may very per chat network.
- There is no convention on how the Extra Symmetric Key should be used.
</details>


[otr4j]: <https://github.com/otr4j/otr4j> "otr4j with OTRv4 support"
[OTRv4]: <https://github.com/otrv4/otrv4> "OTRv4 specification"
[OTR3]: <https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html> "OTR 3 specification"
[echonetwork]: <https://github.com/otr4j/echonetwork> "Minimal infrastructure for testing interoperability of OTR-libraries"

