# Oath Recovery Tool

Recover your Oath wallet or escrow funds independently — no server, no app, no dependencies.

## When to use this

- Oath is offline or unreachable
- You want to move your funds to another wallet (Phantom, Backpack, etc.)
- You exported a recovery file or key shares from Oath Settings > Backup & Recovery

## Download

1. Click the green **Code** button at the top of this page
2. Click **Download ZIP**
3. Open your Downloads folder and unzip the file
4. Open the unzipped folder and double-click **index.html** — it will open in your browser

## How to use

1. Drop your file(s) into the page:
   - **Wallet recovery file** (1 file) — enter your recovery password when prompted
   - **Escrow key shares** (2 files) — from you and one other party
2. Click "Decrypt Key" or "Reconstruct Key"
3. Copy the private key and import it into any Solana wallet (Phantom, Backpack, etc.)

## Security

- Runs 100% in your browser. Nothing is sent to any server.
- Close the tab when you're done.
- Never share your private key or recovery files with anyone.
- **Oath will never ask you to use this tool.** If someone directed you here, they may be trying to scam you.

## Technical details

- Zero dependencies — uses Web Crypto API (PBKDF2, AES-256-GCM) and BigInt math for ed25519
- Works offline after the page loads
- MIT licensed
