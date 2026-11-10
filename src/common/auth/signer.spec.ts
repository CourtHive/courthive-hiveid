import { JwtService } from '@nestjs/jwt';
import { generateKeyPairSync } from 'crypto';

import { isEs256SigningEnabled, resetSigningKeyCacheForTests, signJwt } from './signJwt';
import { getJwks, resetKeyCacheForTests } from './jwtKeys';
import { verifyJwt } from './verifyJwt';

// A throwaway ES256 keypair generated per run — never the ecosystem's real
// keypair. Proves the ported signer mints ES256 tokens that the ported
// verifier accepts, and that the downgrade/fail-closed guards hold.
const KID = 'es256-test-kid';
const keypair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const PRIVATE_PEM = keypair.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
const PUBLIC_PEM = keypair.publicKey.export({ type: 'spki', format: 'pem' }) as string;

function headerOf(token: string): { alg?: string; kid?: string } {
  return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}

describe('signer infrastructure (ES256)', () => {
  const jwt = new JwtService({ secret: 'test-hs-secret' });
  const savedEnv = { ...process.env };

  beforeEach(() => {
    process.env.JWT_PRIVATE_KEY = PRIVATE_PEM;
    process.env.JWT_PUBLIC_KEY = PUBLIC_PEM;
    process.env.JWT_KID = KID;
    process.env.JWT_SIGN_ES256 = 'true';
    delete process.env.JWT_ACCEPT_HS256;
    resetSigningKeyCacheForTests();
    resetKeyCacheForTests();
  });

  afterAll(() => {
    process.env = savedEnv;
    resetSigningKeyCacheForTests();
    resetKeyCacheForTests();
  });

  it('signs ES256 (kid header) and verifies round-trip', async () => {
    expect(isEs256SigningEnabled()).toBe(true);
    const token = await signJwt(jwt, { sub: 'u1' });
    expect(headerOf(token)).toMatchObject({ alg: 'ES256', kid: KID });
    const payload = await verifyJwt<{ sub: string }>(jwt, token);
    expect(payload.sub).toBe('u1');
  });

  it('publishes the public key via JWKS without private material', () => {
    const jwks = getJwks();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kid: KID, alg: 'ES256', use: 'sig', kty: 'EC' });
    expect(jwks.keys[0]).not.toHaveProperty('d');
  });

  it('fails closed when no verify key matches the kid', async () => {
    const token = await signJwt(jwt, { sub: 'u1' });
    delete process.env.JWT_PUBLIC_KEY;
    resetKeyCacheForTests();
    await expect(verifyJwt(jwt, token)).rejects.toThrow('Unknown token signing key');
  });

  it('rejects alg:none (downgrade guard)', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify({ sub: 'u1' })).toString('base64url');
    await expect(verifyJwt(jwt, `${header}.${body}.`)).rejects.toThrow('Unsigned');
  });

  it('dual-accepts HS256, and rejects it when JWT_ACCEPT_HS256=false', async () => {
    delete process.env.JWT_SIGN_ES256; // fall back to HS256 signing (instance secret)
    resetSigningKeyCacheForTests();
    const token = await signJwt(jwt, { sub: 'u1' });
    expect(headerOf(token).alg).toBe('HS256');
    await expect(verifyJwt<{ sub: string }>(jwt, token)).resolves.toMatchObject({ sub: 'u1' });

    process.env.JWT_ACCEPT_HS256 = 'false';
    await expect(verifyJwt(jwt, token)).rejects.toThrow('no longer accepted');
  });
});
