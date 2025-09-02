# Trading Authority (One‑Click Trading)

A minimal demo of a session‑key (“Trading Authority”) derived from a single EIP‑712 signature. It enables one‑click actions without repeated wallet prompts and keeps the primary wallet isolated. Used to power One‑Click Trading (OCT) in production. Ref: https://twitter.com/HubbleExchange/status/1694139074804863053

## Tech
- HTML + Tailwind (CDN)
- viem (RPC/wallet)
- `@scure/bip39`, `@scure/bip32` (HD derivation)
- `crypto-js` (AES encryption)
- Shikiji (code highlighting)

## Quick start
Static files; open directly or serve locally.

- Open `src/index.html` in a browser, or
- Serve the folder:
  - `python3 -m http.server 4173` → http://localhost:4173/src/index.html
  - `npx serve -l 4173` → http://localhost:4173/src/index.html

Requirements: a browser wallet (EIP‑1193) and public RPC access.

## Security notes
- The derived private key is encrypted with a user password and stored in `localStorage` (demo only).
- In production, scope the authority via a gatekeeper contract (assets/limits/expiry) and choose storage appropriate to your threat model (e.g., session‑bound keys, hardware‑assisted, remote signers).
- Enforce strong passwords; never persist unencrypted keys.

## License
MIT

