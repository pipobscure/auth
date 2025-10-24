import * as Assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import * as JWT from '@pipobscure/jwt';
import * as Store from '@pipobscure/store';
import { Accounts } from './accounts.ts';

describe('accounts', async () => {
	let accounts: Accounts | undefined;
	let recoveryKeys: CryptoKeyPair | undefined;
	let signingKeys: CryptoKeyPair | undefined;
	let challenge: { challenge: string; keys: string[] } | undefined;
	let jwt: string | undefined;
	before(async () => {
		[recoveryKeys, signingKeys] = await Promise.all([
			await crypto.subtle.generateKey(
				{
					name: 'RSASSA-PKCS1-v1_5',
					modulusLength: 1026,
					publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
					hash: 'SHA-256',
				},
				true,
				['sign', 'verify'],
			),
			await crypto.subtle.generateKey(
				{
					name: 'RSASSA-PKCS1-v1_5',
					modulusLength: 1026,
					publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
					hash: 'SHA-256',
				},
				true,
				['sign', 'verify'],
			),
		]);
		Assert.ok(recoveryKeys);
		Assert.ok(signingKeys);
	});
	it('can create an Accounts object', async () => {
		const backend = new Store.Memory();
		const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, [
			'sign',
			'verify',
		]);
		Assert.ok(backend);
		Assert.ok(key);
		accounts = new Accounts(backend, key);
		Assert.ok(accounts);
	});
	it('can create an account', async () => {
		Assert.ok(accounts);
		Assert.ok(recoveryKeys);
		const recovery = await crypto.subtle.exportKey('jwk', recoveryKeys.publicKey);
		delete recovery.alg;
		delete recovery.key_ops;
		await accounts.createAccount('test-user', 'Test User', recovery);
	});
	it('can fetch acount data', async () => {
		Assert.ok(accounts);
		Assert.ok(recoveryKeys);
		const account = await accounts.getAccount('test-user');
		Assert.ok(account);
		Assert.equal(account.username, 'test-user');
		Assert.equal(account.displayname, 'Test User');
	});
	it('can create a challenge', async () => {
		Assert.ok(accounts);
		challenge = (await accounts.challenge('tests', 'test-user')) ?? undefined;
		Assert.ok(challenge);
	});
	it('can add a key', async () => {
		Assert.ok(accounts);
		Assert.ok(signingKeys);
		Assert.ok(challenge);
		const result = await accounts.addKey(
			'tests',
			await JWT.sign('RS256', signingKeys.privateKey, Uint8Array.fromBase64(challenge.challenge)),
			'test-user',
			'test-key',
			await crypto.subtle.exportKey('jwk', signingKeys.publicKey),
			'RS256',
		);
		challenge = undefined;
		Assert.ok(result);
		const account = await accounts.getAccount('test-user');
		Assert.ok(account);
		Assert.ok(account.keys['test-key']);
	});
	it('can create another challenge', async () => {
		Assert.ok(accounts);
		challenge = (await accounts.challenge('tests', 'test-user')) ?? undefined;
		Assert.ok(challenge);
	});
	it('can respond to a challenge', async () => {
		Assert.ok(accounts);
		Assert.ok(signingKeys);
		Assert.ok(challenge);
		const result = await accounts.response(
			'tests',
			'test-user',
			await JWT.sign('RS256', signingKeys.privateKey, Uint8Array.fromBase64(challenge.challenge)),
			'test-key',
			'RS256',
		);
		challenge = undefined;
		Assert.ok(result);
	});
	it('can issue a jwt', async () => {
		Assert.ok(accounts);
		jwt =
			(await accounts.jwtIssue('test-user', { aud: 'test', scope: ['urn:accounts:test'] })) ??
			undefined;
		Assert.ok(jwt);
	});
	it('can get the claims of a jwt', async () => {
		Assert.ok(accounts);
		Assert.ok(jwt);
		const claims = await accounts.jwtClaims(jwt);
		Assert.ok(claims);
		Assert.equal(claims.aud, 'test');
		Assert.deepEqual(claims.scope, ['urn:accounts:test']);
	});
	it('can revoke a jwt', async () => {
		Assert.ok(accounts);
		Assert.ok(jwt);
		Assert.ok(await accounts.jwtRevoke(jwt));
		Assert.ok(!(await accounts.jwtClaims(jwt)));
	});
	it('can delete a key', async () => {
		Assert.ok(accounts);
		Assert.ok(await accounts.delKey('test-user', 'test-key'));
		const { keys } = (await accounts.getAccount('test-user')) ?? {};
		Assert.ok(keys);
		Assert.ok(!keys['test-key']);
	});
});
