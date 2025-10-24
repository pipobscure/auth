import * as Assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import { isJWK } from './jwk.ts';

describe('jwk', () => {
	describe('RSA', () => {
		let publicKey: undefined | JsonWebKey;
		let privateKey: undefined | JsonWebKey;
		before(async () => {
			const pair = await crypto.subtle.generateKey(
				{
					name: 'RSASSA-PKCS1-v1_5',
					modulusLength: 1026,
					publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
					hash: 'SHA-256',
				},
				true,
				['sign', 'verify'],
			);
			[publicKey, privateKey] = await Promise.all([
				crypto.subtle.exportKey('jwk', pair.publicKey),
				crypto.subtle.exportKey('jwk', pair.publicKey),
			]);
		});
		it('validates a public key', () => {
			Assert.ok(isJWK(publicKey));
		});
		it('refuses a private key', () => {
			Assert.ok(isJWK(privateKey));
		});
		it('removed private data from private key', () => {
			Assert.deepEqual(privateKey, publicKey);
		});
	});
	describe('EC', () => {
		let publicKey: undefined | JsonWebKey;
		let privateKey: undefined | JsonWebKey;
		before(async () => {
			const pair = await crypto.subtle.generateKey(
				{
					name: 'ECDSA',
					namedCurve: 'P-256',
					hash: 'SHA-256',
				},
				true,
				['sign', 'verify'],
			);
			[publicKey, privateKey] = await Promise.all([
				crypto.subtle.exportKey('jwk', pair.publicKey),
				crypto.subtle.exportKey('jwk', pair.publicKey),
			]);
		});
		it('validates a public key', () => {
			Assert.ok(isJWK(publicKey));
		});
		it('refuses a private key', () => {
			Assert.ok(isJWK(privateKey));
		});
		it('removed private data from private key', () => {
			Assert.deepEqual(privateKey, publicKey);
		});
	});
});
