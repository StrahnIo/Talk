# ZSMTP Plugins

Layer-2 features that run privately between two entities over ZSMTP, rather
than being broadcast on the network. These are candidates to be proposed as
future ZIPs and implemented natively as server plugins.

## Proof-of-activity / proof-of-funds

A circuit where a sender proves they **currently own a specific UTXO or a
combination of UTXOs** whose total value equals or exceeds a given transaction
value `X` ZEC — **without revealing which UTXO or what their address is**.

Built from **Merkle membership proofs** combined with a **range proof**.

Services can use this for:

- Anti-fraud measures.
- Invoicing / credit checks.
- "Free trial" eligibility (prove you can afford the product without revealing
  holdings).

### Feasibility notes

- This is the Sapling/Orchard spend-statement machinery with a different
  verifier. Budget it as a **major circuit effort**, not a quick plugin.
- Proving ownership then spending the same note is fine: the nullifier only
  appears at spend, so the proof does not reveal it. No blocking issue, just
  engineering.

## Loyalty proofs

Scenario: a company wants to give you an airdrop, or verify your loyalty,
**without logging all your transactions**.

1. You and the company agree on a shared session secret.
2. The company server generates a **tree of all of its addresses** and gives
   you the tree and its root.
3. A circuit privately computes that your address(es) — the ones you hold
   spending keys for — have **spent a total of more or less than `X` ZEC**
   across all addresses in the tree, from any number of your own addresses.

The proof reveals **none** of:

- Which addresses were paid from.
- Which addresses were paid into.
- The amounts, or the times.

### Feasibility notes

- The most original idea in the plugin set and the most interesting. It is a
  genuinely novel construction: company address-tree + user spend-keys.
- Real complexity: aggregating *spent amounts* requires the user's note
  plaintexts and a balance-summing circuit.
- Like proof-of-funds, this deserves its own grant-sized budget.

## Other plugin ideas

1. **Conditional / recurring payments** — per-period invoices bound by the same
   K-memo link (a subscription is a series of sealed invoices).
2. **Private payment requests** — a ZSMTP-resolved pay-to-URI carrying an
   ephemeral address + expected amount, no identity.
3. **Threshold spend (FROST over ZSMTP)** — institutional/DAO receiving where
   the IVK holder is a quorum, no single point of failure.
4. **Proof of non-custody** — a circuit proving a server never spent user funds
   (reconciles with the proof-of-funds machinery).
5. **Private messaging over the same session** — ZSMTP as a general sealed
   channel, payments being one payload type.

## Invite

If you want to know whether a specific thing can be circuit-ised, describe the
idea and it will be evaluated for whether it can exist as a future plugin.
