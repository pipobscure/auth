# @pipobscure/auth

**Authentication and Account Management Library**

`@pipobscure/auth` provides a minimal, extensible TypeScript API for managing user accounts, device keys, authentication challenges, and JWT token issuance.  
It is built around strong cryptographic primitives, [JWK](https://datatracker.ietf.org/doc/html/rfc7517) keys, and WebAuthn-style challenge–response authentication.

---

## ✨ Features

- 🔐 WebAuthn-style authentication using signed challenges
- 🧩 Key registration and attestation handling
- 🪪 JWT issuance and verification (via [`@pipobscure/jwt`](https://www.npmjs.com/package/@pipobscure/jwt))
- 🧾 Structured storage abstraction (via [`@pipobscure/store`](https://www.npmjs.com/package/@pipobscure/store))
- ⚙️ TypeScript-native and standards-aligned

---

## 📦 Installation

```bash
npm install @pipobscure/auth
```

or with Yarn:

```bash
yarn add @pipobscure/auth
```

---

## 🚀 Usage

```ts
import { Accounts } from '@pipobscure/auth'
import { MemoryBackend } from '@pipobscure/store'

// Create a store backend and signing key
const backend = new MemoryBackend()
const key = await crypto.subtle.generateKey(
  { name: 'HMAC', hash: 'SHA-256' },
  true,
  ['sign', 'verify']
)

const accounts = new Accounts(backend, key)

// Create an account
await accounts.createAccount('alice', 'Alice Doe', {
  kty: 'RSA',
  e: 'AQAB',
  n: '...' // recovery JWK
})

// Generate a login/registration challenge
const { challenge } = await accounts.challenge('device123', 'alice')

// Register a new key
await accounts.addKey(
  'device123',
  'BASE64_SIGNATURE',
  'alice',
  'key1',
  { kty: 'EC', crv: 'P-256', x: '...', y: '...' },
  'ES256'
)

// Verify a login response
const valid = await accounts.response(
  'device123',
  'alice',
  'BASE64_SIGNATURE',
  'key1',
  'ES256'
)

// Issue a JWT for authenticated sessions
if (valid) {
  const token = await accounts.jwtIssue('alice', { role: 'user' })
  console.log('JWT:', token)
}
```

---

## 🧠 Conceptual Flow

1. **Account Creation** → `createAccount(username, displayname, recovery)`
2. **Key Registration** → `challenge()` → `addAttestation()` / `addKey()`
3. **Authentication** → `challenge()` → `response()`
4. **JWT Issuance** → `jwtIssue()`

---

## 🧩 API Reference

### `class Accounts`

#### **Constructor**
```ts
new Accounts(backend: Backend, key: CryptoKey)
```
- `backend`: A persistence backend (e.g. from `@pipobscure/store`).
- `key`: A `CryptoKey` used for signing JWTs.

---

#### **getAccount(username: string): Promise<Account | null>**
Retrieve an existing account or `null` if it doesn’t exist.

---

#### **createAccount(username, displayname, recovery): Promise<void>**
Create a new account with:
- `username` (canonicalized)
- `displayname`
- `recovery` (JWK)
- Metadata: `id`, `created`, `modified`, and `keys` object

Throws if the account already exists.

---

#### **challenge(devid, username): Promise<{ challenge, keys, userid } | null>**
Generate a new authentication challenge for a given device and user.

---

#### **addKey(devid, signature, username, keyid, key, algorithm): Promise<void>**
Register a new device key for a user after validating a signed challenge.

---

#### **addAttestation(devid, signature, username, attestation, algorithm): Promise<void>**
Extracts key information from a CBOR-encoded attestation and registers it.  
A convenience wrapper around `addKey()`.

---

#### **response(devid, username, signature, keyid, algorithm): Promise<boolean>**
Validate a challenge–response authentication attempt.  
Returns `true` on success, `false` otherwise.

---

#### **delKey(username, keyid): Promise<boolean>**
Delete a registered key from a user account.  
Returns `false` if the key does not exist.

---

#### **jwtIssue(username, claims): Promise<string | null>**
Issue a signed JWT for the given user.  
Automatically includes:
- `iss`, `iat`, `sub`, and `name` claims

Returns the signed token string or `null` if issuance fails.

---

## 🪪 Types

```ts
type Account = {
  id: string
  username: string
  displayname: string
  recovery: JsonWebKey
  keys: Record<string, JsonWebKey>
  created: number
  modified: number
}
```

---

## ⚙️ Development

```bash
npm run build   # Compile TypeScript
npm test        # Run unit tests
npm run format  # Auto-format code
```

---

## 🧾 License

© [Philipp Dunkel](https://github.com/pipobscure) [EUPL v1.2](https://eupl.eu/1.2/en)
