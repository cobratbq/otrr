# otrr

OTR version 3 implementation in Rust.

__warning__ this is a work-in-progress with current focus being on the functional implementation of a design that takes security into account.

## Warning

- crate `dsa` disclaimer states that there has not been thorough verification: functionality only

## Architecture

- OTRv3 only (OTRv2 and earlier not supported)
- Structured for security:
  - security-sensitive primitives in separate module
  - strictly separated states resulting in strictly separated secrets
- __not__ multi-threaded

## Design

- Authenticated Key Exchange (AKE)
- Socialist Millionaire's Protocol (SMP)
- Fragmentation

<details>
  <summary>Checklist</summary>

> ☐: feature, ☑: implemented, ✔: verified

__Functionality__:

- ☐ Authenticated Key Exchange (AKE)
- ☐ Socialist Millionaire's Protocol (SMP)
- ☐ Extra Symmetric Key
  - ☐ TLV `8`
  - __Known issue__: there is no convention on how this key should be used.
- ☑ Fragmentation:
  - ☑ Assemble fragments of incoming message.
  - ☐ Fragment outgoing messages.

__Operational__:
- ☐ ...

__Developmental__:

- ☐ Error do not propagate too far s.t. details leak to the client.
- ☐ Threading design choices and in-logic callbacks (into client) are not too restricting (i.e. cause problems)
- ☐ Need thread-safety for top-level API?
- ☐ ...
</details>
