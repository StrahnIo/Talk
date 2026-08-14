# Attestation

The sender learns the recipient's **shielded address** and their **public
encryption key** through attestation during the ZSMTP exchange. The server
attests to **both**: the address (where to pay) and the pubkey (how to encrypt
the invoice) come from the same attested identity, bound by one domain-key
signature.

## Why both

- **Address** alone is insufficient: the sender needs to know *where* to pay.
- **Pubkey** alone is insufficient: without a binding, a malicious server could
  supply a recipient's address but its own pubkey, letting it decrypt the
  invoice it is supposed to be blind to.
- Attesting to both under one signature prevents **pubkey substitution**: the
  sender encrypts the invoice to the same identity it was told to pay.

## Issuance modes

The "request shielded address" step takes an explicit flag:

- **`ephemeral`** — a fresh, one-shot address generated on demand per request,
  plus a correspondingly fresh encryption pubkey. No identity signature. This is
  the private-recipient default and preserves unlinkability across payments.
- **`attested`** — a stable address + stable pubkey, signed by the server / a
  recognised identity instrument. Used by exchanges and public identities whose
  deposit address is public anyway.

In both modes the address and pubkey are signed together by the server's domain
key. In `attested` mode an additional signature from a recognised identity
instrument (keyserver public key, or later an entry in the Zcash ledger) can
anchor the address to a real-world identity.

## Flow

1. Sender requests an attestation for a queried user, with an `ephemeral` or
   `attested` flag.
2. Server generates (ephemeral) or selects (attested) an address + pubkey pair.
3. Server signs `(address, pubkey, user, flags, session)` with its domain key.
4. Sender verifies the domain-key signature, binds the pubkey to the address,
   and uses the pubkey to encrypt the invoice.

## Modularity

Attestation is behind an `Attester` trait so the anchoring mechanism can be
swapped:

| Trait | v1 impl | Swappable to |
|---|---|---|
| `Attester` | `DomainKeyAttester` | keyserver attestation, on-ledger anchoring |

The identity instrument question (keybase.io was shut down in 2023) is open —
see O9 in [`decisions.md`](decisions.md).
