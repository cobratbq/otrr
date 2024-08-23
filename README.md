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

## Changelog

<details>
  <summary>Changelog</summary>

__0.7.2__

- Fragment-assembly: set maximum limit of 100 incomplete messages. After reaching this limit, the oldest message will be removed from the assembler.
- Marked message-queuing as "won't fix"; explanation added to "Known issues" section.
- Added changelog section in README.md.

__0.7.1__

- Moved working notes to lib.rs comments.

__0.7.0__

Initial release.

</details>

## Design

`TODO write design considerations here`

``TODO document implementation considerations, such as periodically calling `expire` to facilitate session expiration. (Or find a good way to have it timed, thread-safe without causing interference.)``

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
  - ☑ Manual verification (SSID)
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
  - ☑ Limit number of incomplete distinct messages for OTRv4.
- ☐ Heartbeat-messages: keep session alive and ensure regular key rotation.
- ✕ Store plaintext message for transmission under right circumstances (i.e. `REQUIRE_ENCRYPTION` policy, in-progress AKE, etc.)  
  _This is removed from otr4j and will not be implemented here. See "known issues" below for details._
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

- Fragments and reassembly (exact limits open for discussion):
  - ☑ Maximum number of incomplete messages: `100`
  - ☑ Maximum fragment size: `250 kiB`
  - ☑ Maximum message size: `100 MiB`
  - ☐ Maximum over-all memory usage for fragments store
  - ☑ Logging reports on dropped fragments/messages that exceed limits.
- ☑ The _interactive DAKE_ is an independent state-machine. This ensures that the protocol only transitions away after DAKE has completed successfully. It is not possible to trigger DAKE starts causing OTRv4 to transition away from encrypted-messaging state.
- ☑ Single instance of `Account` represents single account on a chat network: allows for specific identity (_DSA keypair_), chat network/transport.
- ☐ Per-account thread-safe implementation. (Not yet determined necessary.)  
  _Given that most messages can be processed one at a time, most benefit is derived from having separate tasks for session expiration and heartbeats. However, these may be interleaved with message processing._

__Developmental__:

- ☑ No logic for managing multiple accounts:  
  _We keep this separated and up to the client to implement as necessary. Essentially, just tying the `Account` to the corresponding chat account logic is sufficient, and additional management risks prescribing a certain structure to the host application (e.g. chat application)._
- ☐ API for managing multiple accounts, keys, policies?
- ☐ Unit tests: too few tests, even though rust syntax is that expressive.
- ☐ Resilient to faulty implementations of `Host` as provided by the client.  
    _At this moment it is not clear how to do this: `std::panic::catch_unwind` is not guaranteed to catch and handle all panics._

</details>

## Known issues

- (Will not be implemented) __Message-queue for delayed sending__: the idea is to queue messages under certain policies or when sending messages while the (D)AKE is in progress. However, as of OTR version 3, instance-tags were added to support distinguishing and identifying multiple clients operating under the same account when OTR sessions are active. Upon establishing an OTR session, sessions may be established simultaneously for each of the active clients - each having their own instance-tag. Stored messages would be sent to the (first) established session, which may not be the client you intended the messages to go to. In addition, the client that supports only lower protocol versions, will likely establish a session fastest.
- How to deal with multiple instances, "default instance", "selected/active instance"? Especially when dealing with incidental reception of plaintext messages while encrypted session is established for some instance.
- The OTR specification documents that any message payload is in UTF-8 and _may contain_ HTML. However, this makes it ambiguous for how the content should be interpreted and results and risks may very per chat network.
- There is no convention on how the Extra Symmetric Key should be used.


[otr4j]: <https://github.com/otr4j/otr4j> "otr4j with OTRv4 support"
[OTRv4]: <https://github.com/otrv4/otrv4> "OTRv4 specification"
[OTR3]: <https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html> "OTR 3 specification"
[echonetwork]: <https://github.com/otr4j/echonetwork> "Minimal infrastructure for testing interoperability of OTR-libraries"

