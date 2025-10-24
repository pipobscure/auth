import { ok as assert } from 'node:assert/strict';
import * as CR from 'node:crypto';
import * as JWT from '@pipobscure/jwt';
import { type Backend, Frontend } from '@pipobscure/store';
import { extractCredentialData } from './attestation.ts';
import { assertJWK, isJWK } from './jwk.ts';

type Timestamp = number;

export class Accounts {
	#store;
	#key: CryptoKey;
	constructor(backend: Backend, key: CryptoKey) {
		this.#store = new Frontend(backend);
		this.#key = key;
	}
	async getAccount(username: string) {
		const data = await this.#store.json(this.#identify('user', username));
		if (!data) return null;
		assertAccount(data);
		return data;
	}
	async createAccount(username: string, displayname: string, recovery: JsonWebKey) {
		username = canon(username);
		const [exists, token] = await Promise.all([
			this.#store.has(this.#identify('user', username)),
			this.#store.token(this.#identify('user', username)),
		]);
		if (exists) throw new Error('user exists');
		const id = userid(username);
		const account = {
			id,
			username,
			displayname,
			recovery,
			keys: {},
			created: Date.now(),
			modified: Date.now(),
		};
		assertAccount(account);
		const [writeUser, writeId] = await Promise.all([
			this.#store.set(this.#identify('user', username), account, { token }),
			this.#store.set(this.#identify('user', 'id', `${id}`), { username }),
		]);
		if (!(writeUser && writeId)) throw new Error('failed to create user');
	}

	async challenge(devid: string, username: string) {
		username = canon(username);
		const [account, token] = await Promise.all([
			this.#store.json(this.#identify('user', username)),
			this.#store.token(this.#identify('user', devid, 'challenge')),
		]);
		assertAccount(account);
		const challenge = CR.randomBytes(48).toString('base64');
		const keys = Object.keys(account.keys);
		const stored = await this.#store.set(
			this.#identify('user', devid, 'challenge'),
			{
				challenge,
				keys,
				issued: Date.now(),
			},
			{ token },
		);
		if (!stored) {
			return null;
		}
		return { challenge, keys, userid: account.id };
	}
	async addKey(
		devid: string,
		signature: Base64,
		username: string,
		keyid: string,
		key: JsonWebKey,
		algorithm: JWT.Algorithm,
	) {
		assertJWK(key);
		username = canon(username);
		const [challenge, token, account] = await Promise.all([
			this.#store.json(this.#identify('user', devid, 'challenge')),
			this.#store.token(this.#identify('user', username)),
			this.#store.json(this.#identify('user', username)),
		]);
		assert(challenge?.challenge);
		assertAccount(account);
		if (account.keys[keyid]) throw new Error('duplicate key');
		const jwk = await crypto.subtle.importKey('jwk', key, JWT.ALGORITHMS[algorithm], false, [
			'verify',
		]);
		const valid = await JWT.verify(
			algorithm,
			jwk,
			signature,
			Buffer.from(challenge.challenge, 'base64'),
		);
		if (!valid) throw new Error('invalid signature');
		account.keys[keyid] = key;
		account.modified = Date.now();
		return await this.#store.set(this.#identify('user', username), account, { token });
	}
	async addAttestation(
		devid: string,
		signature: Base64,
		username: string,
		attestation: Uint8Array | ArrayBuffer,
		algorithm: JWT.Algorithm,
	) {
		if (!(attestation instanceof ArrayBuffer)) {
			attestation = attestation.buffer.slice(
				attestation.byteOffset,
				attestation.byteOffset + attestation.byteLength,
			) as ArrayBuffer;
		}
		const credentials = extractCredentialData(attestation);
		return await this.addKey(
			devid,
			signature,
			username,
			credentials.id,
			credentials.jwk,
			algorithm,
		);
	}
	async response(
		devid: string,
		username: string,
		signature: Base64,
		keyid: string,
		algorithm: JWT.Algorithm,
	) {
		username = canon(username);
		const [token, original, account] = await Promise.all([
			this.#store.token(this.#identify('user', devid, 'challenge')),
			this.#store.json(this.#identify('user', devid, 'challenge')),
			this.#store.json(this.#identify('user', username)),
		]);
		try {
			assertAccount(account);
			assert(isObject(original));
			assert(Array.isArray(original.keys));
			assertBase64(original.challenge);
			assert(original.keys);
			assert(account.keys[keyid]);
			assert(original.keys.includes(keyid));
			const key = await crypto.subtle.importKey(
				'jwk',
				account.keys[keyid],
				JWT.ALGORITHMS[algorithm],
				false,
				['verify'],
			);
			const valid = await JWT.verify(
				algorithm,
				key,
				signature,
				Buffer.from(original.challenge, 'base64'),
			);
			if (!valid) throw new Error('invalid signature');
			await this.#store.set(
				this.#identify('user', devid, 'challenge'),
				{
					signature,
					keyid,
					valid: true,
					timestamp: Date.now(),
				},
				{ token },
			);
			return true;
		} catch {
			await this.#store.set(
				this.#identify('user', devid, 'challenge'),
				{
					signature,
					keyid,
					valid: true,
					timestamp: Date.now(),
				},
				{ token },
			);
			return false;
		}
	}
	async delKey(username: string, keyid: string) {
		username = canon(username);
		const [token, account] = await Promise.all([
			this.#store.token(this.#identify('user', username)),
			this.#store.json(this.#identify('user', username)),
		]);
		assertAccount(account);
		if (!account.keys[keyid]) return false;
		delete account.keys[keyid];
		account.modified = Date.now();
		return await this.#store.set(this.#identify('user', username), account, { token });
	}

	async jwtIssue(username: string, cnt: Omit<Claims, 'sub' | 'name' | 'iss' | 'iat'>) {
		const account = await this.getAccount(username);
		if (!account) return null;
		const iss = this.#identify(username);
		const iat = Date.now();
		const sub = account.username;
		const name = account.displayname;
		const jwt = await JWT.generate(
			Object.assign({ iss, iat, sub, name }, cnt, { iss, iat, sub, name }),
			this.#key,
		);
		if (!(await this.#store.set(this.#identify('token', jwt), { jwt }))) return null;
		return jwt;
	}
	async jwtRevoke(jwt: string) {
		const token = await this.#store.token(this.#identify('token', jwt));
		return this.#store.delete(this.#identify('token', jwt), { token });
	}
	async jwtClaims(jwt: string) {
		try {
			if (!(await this.#store.has(this.#identify('token', jwt)))) return null;
			const claims = (await JWT.extract(jwt, this.#key)) as Claims;
			return claims;
		} catch {
			return null;
		}
	}

	#identify(primary: string, ...parts: string[]) {
		return [['urn', 'account', primary].join(':'), ...parts].join('/');
	}
	static algorithm(cose: number) {
		switch (cose) {
			case -257:
				return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }; // RS256
			case -258:
				return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }; // RS384
			case -259:
				return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }; // RS512
			case -37:
				return { name: 'RSA-PSS', hash: 'SHA-256' }; // PS256
			case -38:
				return { name: 'RSA-PSS', hash: 'SHA-384' }; // PS384
			case -39:
				return { name: 'RSA-PSS', hash: 'SHA-512' }; // PS512
			case -7:
				return { name: 'ECDSA', namedCurve: 'P-256' }; // ES256
			case -35:
				return { name: 'ECDSA', namedCurve: 'P-384' }; // ES384
			case -36:
				return { name: 'ECDSA', namedCurve: 'P-521' }; // ES512
			default:
				throw new Error('Unsupported COSE algorithm');
		}
	}
	static isAccount(data: any): data is Account {
		if (
			!isObject(data) ||
			!isBase64(data.id) ||
			!isString(data.username) ||
			!Number.isInteger(data.created) ||
			!Number.isInteger(data.modified) ||
			!isJWK(data.recovery) ||
			!isObject(data.keys)
		)
			return false;
		for (const key of Object.values(data.keys)) {
			if (!isJWK(key)) return false;
		}
		return true;
	}
	static isJsonPublicKey(data: any): data is JsonWebKey {
		return isJWK(data);
	}
}

export type Account = {
	id: string;
	username: string;
	displayname: string;
	recovery: JsonWebKey;
	keys: Record<string, JsonWebKey>;
	created: Timestamp;
	modified: Timestamp;
};
function assertAccount(data: any): asserts data is Account {
	if (!Accounts.isAccount(data)) throw new TypeError('invalid account object');
}

type Claims = {
	iss: string;
	iat: number;
	sub: string;
	name: string;
	aud: string;
	scope: string[];
	exp?: number;
};

type Base64 = string;
function isBase64(item: any): item is Base64 {
	return isString(item) && /^(?:[a-z0-9/+]{2,4})+={0,2}$/i.test(item);
}
function assertBase64(item: string): asserts item is Base64 {
	assert(isBase64(item));
}

function isObject(item: any) {
	return !!(item && 'object' === typeof item);
}
function isString(item: any): item is string {
	return !!('string' === typeof item && item.length);
}

// used to create a userId during account creation only!
function userid(username: string) {
	const buf = CR.createHash('sha-1')
		.update(Buffer.from(username.toLowerCase()))
		.update(nowBuffer())
		.digest();
	return buf.subarray(0, 8).toBase64();
}
function canon(username: string) {
	username = username.toLowerCase().split(/\s+/).join('');
	assert(/^[a-z][a-z0-9_\-.]+[a-z0-9]$/.test(username));
	return username;
}
function nowBuffer() {
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(BigInt(Date.now()));
	return buf;
}
