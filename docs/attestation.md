# Attestation

Two chained attestations bind a username to a wallet, and the sender learns the
recipient's **shielded address** and **public encryption key** through them
during the ZSMTP exchange.

## Registration attestation `R` (the source of truth)

Created at registration, signed over the **stable binding**:

```
R = Sign(domain_key, { domain, username, master_pubkey, [ivk_commitment], registered_at })
```

Stored with the user. `R` is the canonical, tamper-evident record of
`username ↔ wallet pubkey`. It is created once, at registration.

**Why it exists:** the DB `master_pubkey` column is mutable. If an attacker
edits the database to change a user's pubkey, the live attestation must not
produce a *valid* result. Because the live attestation is anchored to `R` (the
source of truth), a direct DB edit cannot yield a verifying attestation.

## Live server attestation `L` (from `ADDR`)

`ADDR` mints an address for a registered user and anchors it to `R`:

- `L` **includes `R`** and its signature covers `digest(R)`.
- The attested pubkey must equal `R.master_pubkey` (static mode).
- Unknown user → `550 no such user` (no `R` to anchor to).

The sender verifies: `R` is valid, `L` is valid, and `L.pubkey == R.master_pubkey`.

## Why both (address + pubkey)

- **Address** alone is insufficient: the sender needs to know *where* to pay.
- **Pubkey** alone is insufficient: without a binding, a malicious server could
  supply a recipient's address but its own pubkey, letting it decrypt the
  invoice it is supposed to be blind to.
- Attesting to both under one signature prevents **pubkey substitution**.

## Issuance modes

The "request shielded address" step takes an explicit flag:

- **`ephemeral`** — a fresh, one-shot address generated on demand per request.
  In static mode (no IVK), the pubkey is still the registered `master_pubkey`
  (anchored to `R`); only the address rotates. Preserves unlinkability.
- **`attested`** — a stable address + stable pubkey, signed by the server / a
  recognised identity instrument. Used by exchanges and public identities whose
  deposit address is public anyway.

### Dynamic addresses (optional IVK)

If a user registers an **IVK** (optional), `ADDR` can mint dynamic addresses:

- Pick a random diversifier `d` → `g_d = DiversifyHash(d)` → `pk_d = [ivk]·g_d`.
- Address = `(d, pk_d)`. Each request gets a fresh, unlinkable address.
- `d` is given to the sender as a **one-way address ID**: it reveals nothing
  about the wallet (diversifiers are unlinkable by design), and is safe to share.
- Tamper-evidence: `pk_d` must verify against `ivk` + `d`; an attacker would need
  to rewrite the `ivk` committed in `R` for a forged address to verify.

**Security note:** in Zcash, the IVK is what scans and decrypts incoming notes.
Handing the IVK to the server enables address generation but is an explicit
*scanning delegation* — the server can detect payments to addresses it derives.
This is an opt-in per-user tradeoff; by default the server never holds the IVK.

## Sender keyring (authenticate a sender)

Receiving users can build a **server-side keyring** of trusted senders. The
sender's identity (username) rides in the **INVOICE envelope** today; carrying
the sender's attested key + `R` with the message is a follow-on (D22).

- **Bootstrap:** the user's *client* initiates an authentication request (manual
  or background), fetches the sender's server-attested key, verifies the
  attestation, then pins `sender@domain → pubkey` into the keyring. **This is
  not the server's job** — the server never initiates lookups; querying the
  keyring is a later milestone.
- **Trust state computed at delivery** (implemented):
  - sender pinned in the recipient's keyring → `trusted`
  - anonymous sender → `unverified`
  - (with key riding, later) key present but **≠** keyring entry, or signature
    fails → `untrusted` (flagged immediately)
- The server only does keyring matching (+ signature verification once key
  riding lands) — it does not independently verify the sender's `R` against DNS
  (that is the client's job at pin time).

**Privacy:** purely opt-in on both ends. A sender only becomes pinned if they
opt into being attested *and* the receiver chooses to authenticate them.
Anonymous-by-default is preserved — Zcash does not reveal sender addresses.

## Flow (recipient attestation)

1. Sender requests an attestation for a queried user, with an `ephemeral` or
   `attested` flag.
2. Server loads the user's `R`; unknown user → `550`.
3. Server mints the address via the `AddressProvider` (static: registered pubkey
   + fresh address; dynamic: `(d, pk_d)` from IVK).
4. Server emits `L` anchored to `R`.
5. Sender verifies the domain-key signature and the `R`-anchor, binds the pubkey
   to the address, and uses the pubkey to encrypt the invoice.

## Modularity

Address minting is behind a trait; attestation signing currently uses the
domain key directly in the session/daemon (an `Attester` trait is a future
extraction):

| Trait | v1 impl | Swappable to |
|---|---|---|
| `AddressProvider` | `PlaceholderAddressProvider` | `IvkAddressProvider` (owns IVK; may run on its own socket/port) |
| `Attester` (planned) | — (domain-key signing in session) | keyserver attestation, on-ledger anchoring |

The identity instrument question (keybase.io was shut down in 2023) is open —
see O9 in [`decisions.md`](decisions.md).
