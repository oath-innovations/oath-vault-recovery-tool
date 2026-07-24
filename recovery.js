const P = 2n ** 255n - 19n
const N = 2n ** 252n + 27742317777372353535851937790883648493n
const D = mod(-121665n * modInverse(121666n))

const Gx = 15112221349535807912866137220509078750507884956996801397970088037519608547828n
const Gy = 46316835694926478169428394003475163141307993866256225615783033890098355573649n
const G = [Gx, Gy, 1n, mod(Gx * Gy)]
const IDENTITY = [0n, 1n, 1n, 0n]

function mod(a, m = P) {
  return ((a % m) + m) % m
}

function modInverse(a, m = P) {
  a = mod(a, m)
  let [old_r, r] = [a, m]
  let [old_s, s] = [1n, 0n]
  while (r !== 0n) {
    const q = old_r / r
    ;[old_r, r] = [r, old_r - q * r]
    ;[old_s, s] = [s, old_s - q * s]
  }
  return mod(old_s, m)
}

function pointAdd(p1, p2) {
  if (p1[0] === 0n && p1[3] === 0n) return p2
  if (p2[0] === 0n && p2[3] === 0n) return p1
  const [X1, Y1, Z1, T1] = p1
  const [X2, Y2, Z2, T2] = p2
  const A = mod((Y1 - X1) * (Y2 - X2))
  const B = mod((Y1 + X1) * (Y2 + X2))
  const C = mod(T1 * 2n * D * T2)
  const DD = mod(Z1 * 2n * Z2)
  const E = mod(B - A)
  const F = mod(DD - C)
  const GG = mod(DD + C)
  const H = mod(B + A)
  return [mod(E * F), mod(GG * H), mod(F * GG), mod(E * H)]
}

function scalarMult(scalar, point) {
  let result = IDENTITY
  let current = point
  scalar = mod(scalar, N)
  while (scalar > 0n) {
    if (scalar & 1n) result = pointAdd(result, current)
    current = pointAdd(current, current)
    scalar >>= 1n
  }
  return result
}

function bigintToBytes(val) {
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(val & 0xffn)
    val >>= 8n
  }
  return bytes
}

function bytesToBigint(bytes) {
  let val = 0n
  for (let i = bytes.length - 1; i >= 0; i--) {
    val = (val << 8n) | BigInt(bytes[i])
  }
  return val
}

function pointToBytes(point) {
  const [X, Y, Z] = point
  const zi = modInverse(Z)
  const bytes = bigintToBytes(mod(Y * zi))
  if (mod(X * zi) & 1n) bytes[31] |= 0x80
  return bytes
}

function reconstructFromShares(shares) {
  let secret = 0n
  for (let i = 0; i < shares.length; i++) {
    const xi = BigInt('0x' + shares[i].identifier)
    let num = 1n
    let den = 1n
    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue
      const xj = BigInt('0x' + shares[j].identifier)
      num = mod(num * (0n - xj), N)
      den = mod(den * (xi - xj), N)
    }
    const coeff = mod(num * modInverse(den, N), N)
    secret = mod(secret + BigInt('0x' + shares[i].signing_share) * coeff, N)
  }
  return secret
}

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58Encode(bytes) {
  let num = 0n
  for (const b of bytes) num = num * 256n + BigInt(b)
  let str = ''
  while (num > 0n) {
    str = BASE58[Number(num % 58n)] + str
    num /= 58n
  }
  for (const b of bytes) {
    if (b === 0) str = '1' + str
    else break
  }
  return str
}

function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

async function decryptWithPassword(encryptedB64, password, saltB64, ivB64, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  )
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  )
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(ivB64) }, key, b64ToBytes(encryptedB64)
  )
  return new Uint8Array(decrypted)
}

// Scalar → Solana keypair (base58 address + base58 secret)
function scalarToKeypair(secretBytes) {
  const pubBytes = pointToBytes(scalarMult(bytesToBigint(secretBytes), G))
  const keypair = new Uint8Array(64)
  keypair.set(secretBytes, 0)
  keypair.set(pubBytes, 32)
  return { address: base58Encode(pubBytes), secret: base58Encode(keypair) }
}

let files = []

function handleFiles(fileList) {
  for (const f of fileList) {
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const json = JSON.parse(e.target.result)
        if (!json.type) throw new Error('Missing type field')
        files.push({ name: f.name, data: json })
        updateUI()
      } catch (err) {
        showError('Invalid file: ' + err.message)
      }
    }
    reader.readAsText(f)
  }
}

function updateUI() {
  document.getElementById('fileList').innerHTML = files
    .map((f) => `<div class="file-item"><span class="check">&#10003;</span><span>${f.name}</span><span class="type">(${f.data.type})</span></div>`)
    .join('')

  const hasWallet = files.some((f) => f.data.type === 'oath-wallet-recovery')
  const shareCount = files.filter((f) => f.data.type === 'oath-escrow-share').length

  document.getElementById('passwordSection').style.display = hasWallet ? 'block' : 'none'

  const btn = document.getElementById('actionBtn')
  const status = document.getElementById('status')
  if (hasWallet) {
    btn.disabled = false
    btn.textContent = 'Decrypt Key'
    status.textContent = 'Wallet recovery file detected. Enter your password.'
  } else if (shareCount >= 2) {
    btn.disabled = false
    btn.textContent = 'Reconstruct Key'
    status.textContent = shareCount + ' shares loaded. Ready to reconstruct.'
  } else if (shareCount === 1) {
    btn.disabled = true
    btn.textContent = 'Reconstruct Key'
    status.textContent = 'Need 1 more share file (2 required).'
  } else {
    btn.disabled = true
  }
}

async function reconstruct() {
  showError('')
  document.getElementById('result').style.display = 'none'

  try {
    const walletFile = files.find((f) => f.data.type === 'oath-wallet-recovery')
    let secretBytes

    if (walletFile) {
      const password = document.getElementById('passwordInput').value
      if (!password) { showError('Enter your recovery password.'); return }
      const d = walletFile.data
      secretBytes = await decryptWithPassword(d.encrypted_key, password, d.kdf_params.salt, d.iv, d.kdf_params.iterations)
    } else {
      const shares = files.filter((f) => f.data.type === 'oath-escrow-share').map((f) => f.data)
      if (new Set(shares.map((s) => s.group_public_key)).size > 1) {
        showError('Shares are from different escrows!')
        return
      }
      secretBytes = bigintToBytes(reconstructFromShares(shares))
    }

    const { address, secret } = scalarToKeypair(secretBytes)
    document.getElementById('resultAddress').textContent = address
    document.getElementById('resultKey').textContent = secret
    document.getElementById('result').style.display = 'block'
  } catch (err) {
    showError('Error: ' + err.message)
  }
}

function copyKey() {
  navigator.clipboard.writeText(document.getElementById('resultKey').textContent)
  const btn = document.querySelector('.copy-btn')
  btn.textContent = 'Copied!'
  setTimeout(() => (btn.textContent = 'Copy Private Key'), 2000)
}

function showError(msg) {
  document.getElementById('error').textContent = msg
}

function reset() {
  files = []
  document.getElementById('fileList').innerHTML = ''
  document.getElementById('status').textContent = ''
  document.getElementById('passwordSection').style.display = 'none'
  document.getElementById('passwordInput').value = ''
  document.getElementById('actionBtn').disabled = true
  document.getElementById('actionBtn').textContent = 'Reconstruct Key'
  document.getElementById('result').style.display = 'none'
  document.getElementById('fileInput').value = ''
  showError('')
}

const dz = document.getElementById('dropZone')
dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('dragover') })
dz.addEventListener('dragleave', () => dz.classList.remove('dragover'))
dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('dragover'); handleFiles(e.dataTransfer.files) })
