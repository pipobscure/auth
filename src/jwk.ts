import * as Assert from 'node:assert/strict';
import * as AJV from 'ajv';

export const schema = {
	$id: 'https://example.com/schemas/jwk-public-rsa-or-ec.schema.json',
	title: 'RSA or EC Public JSON Web Key (JWK)',
	description:
		'Validates a JSON Web Key that is either an RSA or EC public key, with no private fields.',
	type: 'object',
	oneOf: [
		{
			title: 'RSA public key',
			properties: {
				kty: { const: 'RSA' },
				n: {
					type: 'string',
					pattern: '^[A-Za-z0-9_-]+$',
					description: 'Base64url-encoded modulus.',
				},
				e: {
					type: 'string',
					pattern: '^[A-Za-z0-9_-]+$',
					description: 'Base64url-encoded exponent.',
				},
				use: {
					type: 'string',
					enum: ['sig', 'enc'],
				},
				alg: { type: 'string' },
				kid: { type: 'string' },
				key_ops: {
					type: 'array',
					items: {
						type: 'string',
						enum: ['verify', 'encrypt', 'wrapKey'],
					},
				},
			},
			required: ['kty', 'n', 'e'],
			additionalProperties: false,
		},
		{
			title: 'EC public key',
			properties: {
				kty: { const: 'EC' },
				crv: {
					type: 'string',
					enum: ['P-256', 'P-384', 'P-521', 'secp256k1'],
				},
				x: {
					type: 'string',
					pattern: '^[A-Za-z0-9_-]+$',
					description: 'Base64url-encoded X coordinate.',
				},
				y: {
					type: 'string',
					pattern: '^[A-Za-z0-9_-]+$',
					description: 'Base64url-encoded Y coordinate.',
				},
				use: {
					type: 'string',
					enum: ['sig', 'enc'],
				},
				alg: { type: 'string' },
				kid: { type: 'string' },
				key_ops: {
					type: 'array',
					items: {
						type: 'string',
						enum: ['verify', 'deriveBits', 'deriveKey'],
					},
				},
			},
			required: ['kty', 'crv', 'x', 'y'],
			additionalProperties: false,
		},
	],
	not: {
		anyOf: [
			{ required: ['d'] },
			{ required: ['p'] },
			{ required: ['q'] },
			{ required: ['dp'] },
			{ required: ['dq'] },
			{ required: ['qi'] },
		],
	},
};

const ajv = new AJV.Ajv({ useDefaults: true, removeAdditional: true });
const validate = ajv.compile(schema);

export function isJWK(value: any): value is JsonWebKey {
	if (validate(value)) {
		return true;
	}
	return false;
}
export function assertJWK(value: any): asserts value is JsonWebKey {
	Assert.ok(isJWK(value));
}
