import * as CBOR from 'cbor';
import { assertJWK } from './jwk.ts';

export function extractCredentialData(attestationObject: ArrayBuffer) {
	// Decode the CBOR attestationObject
	const attestation = CBOR.decodeFirstSync(new Uint8Array(attestationObject));
	const authData = new Uint8Array(attestation.authData);

	let offset = 0;
	offset += 32; // rpIdHash
	const flags = authData[offset++] ?? 0;
	offset += 4; // signCount

	// Check if attestedCredentialData is present (bit 6)
	const attestedCredentialDataPresent = !!(flags & 0x40);
	if (!attestedCredentialDataPresent) {
		throw new Error('No attested credential data found in authData');
	}

	// Parse AAGUID
	const device = authData.slice(offset, offset + 16);
	offset += 16;

	// Credential ID length (2 bytes, big endian)
	const credIdLen = ((authData[offset] ?? 0) << 8) | (authData[offset + 1] ?? 0);
	offset += 2;

	// Credential ID
	const credentialId = authData.slice(offset, offset + credIdLen);
	offset += credIdLen;

	// The remainder is the CBOR-encoded COSE public key
	const cosePublicKeyBytes = authData.slice(offset);
	const coseKey = CBOR.decodeFirstSync(cosePublicKeyBytes);

	// Convert COSE -> JWK
	const jwk = coseToJwk(coseKey);

	assertJWK(jwk);
	return {
		id: bufferToBase64Url(credentialId),
		device: bufferToBase64Url(device),
		jwk,
	};
}

/** Convert COSE (decoded CBOR map) to JWK */
function coseToJwk(coseKey: Map<number, any>): JsonWebKey {
	const kty = coseKey.get(1);
	const crv = coseKey.get(-1);
	const x = coseKey.get(-2);
	const y = coseKey.get(-3);
	const n = coseKey.get(-1);
	const e = coseKey.get(-2);

	// EC2 key (most common)
	if (kty === 2) {
		const crvMap: Record<number, string> = {
			1: 'P-256',
			2: 'P-384',
			3: 'P-521',
		};

		return {
			kty: 'EC',
			crv: crvMap[crv] ?? 'P-256',
			x: bufferToBase64Url(x),
			y: bufferToBase64Url(y),
		};
	}

	// RSA key
	if (kty === 3) {
		return {
			kty: 'RSA',
			n: bufferToBase64Url(n),
			e: bufferToBase64Url(e),
		};
	}

	throw new Error(`Unsupported COSE key type: ${kty}`);
}

/** Convert ArrayBuffer/Uint8Array → base64url */
function bufferToBase64Url(buf: ArrayBuffer | Uint8Array): string {
	const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
	Buffer.from(bytes).toString('base64url');
	return Buffer.from(bytes)
		.toString('hex')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}
