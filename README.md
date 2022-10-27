# otrr

OTR version 3 implementation in Rust.

__status__ work-in-progress, "_It builds. There are some tests."

Tests demonstrate an established OTR session, however this only proves that any bugs we might touch are symmetric in nature.

- ☐ correctness?
- ☐ interoperability?

## Warning

- not clear on current status of OTRv4 protocol specification.
- crate `dsa`:
  - disclaimer states it is not thoroughly verified
  - needs changes to expose additional API

```TODO
- write up conclusion of risks below,
- reason about extent of the vulnerability and find sources on whether it is still acceptable,
- recommendation to avoid group is evaluated based on a threat-model requiring a certain minimum number of years of security, (so it depends on what is being discussed whether OTR is adaquate, presumably)
- ...

- risks/limitations of protocol version 3:
  - does not satisfy recent recommendation for DH moduli of `>= 2048`.
  - DH modulus in use is likely candidate for precomputation ()
- Sources to check:
  - [WeakDH](<https://weakdh.org/> "Weak Diffie-Hellman and the Logjam Attack")
  - [LogJam](<https://en.wikipedia.org/wiki/Logjam_(computer_security)>)
  - [DHEat Attack](<https://dheatattack.com/> "DoS attack that can be performed by enforcing the Diffie-Hellman key exchange")
  - [RFC 5114](<https://www.rfc-editor.org/rfc/rfc5114.html>)
```

## Architecture

- OTRv3 only (OTRv2 and earlier are not supported)  
  OTRv4 anticipated: intention to implement, but development of specification seems to be suspended.
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
- ☐ Resilient to faulty implementations of `Host` as provided by the client.  
    _At this moment it is not clear how to do this: `std::panic::catch_unwind` is not guaranteed to catch and handle all panics._

__Known issues__:

- How to deal with multiple instances, "default instance", "selected/active instance"? Especially when dealing with incidental reception of plaintext messages while encrypted session is established for some instance.
- The OTR specification documents that any message payload is in UTF-8 and _may contain_ HTML. However, this makes it ambiguous for how the content should be interpreted and results and risks may very per chat network.
- There is no convention on how the Extra Symmetric Key should be used.
</details>
