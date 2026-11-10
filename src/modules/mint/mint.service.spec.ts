import { BadRequestException, ServiceUnavailableException } from '@nestjs/common';
import { generateKeyPairSync } from 'crypto';
import { JwtService } from '@nestjs/jwt';

import { resetSigningKeyCacheForTests } from 'src/common/auth/signJwt';
import { resetKeyCacheForTests } from 'src/common/auth/jwtKeys';
import { verifyJwt } from 'src/common/auth/verifyJwt';
import { MintService } from './mint.service';

// Throwaway ES256 keypair — never the ecosystem's real keypair. Proves the mint
// signs ES256 tokens the ported verifier accepts, and that the guards hold.
const KID = 'es256-test-kid';
const keypair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const PRIVATE_PEM = keypair.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
const PUBLIC_PEM = keypair.publicKey.export({ type: 'spki', format: 'pem' }) as string;

function headerOf(token: string): { alg?: string; kid?: string } {
  return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}

function payloadOf(token: string): Record<string, any> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
}

describe('MintService', () => {
  const jwt = new JwtService({ secret: 'test-hs-secret' });
  const service = new MintService(jwt);
  const savedEnv = { ...process.env };

  const enableEs256 = () => {
    process.env.JWT_PRIVATE_KEY = PRIVATE_PEM;
    process.env.JWT_PUBLIC_KEY = PUBLIC_PEM;
    process.env.JWT_KID = KID;
    process.env.JWT_SIGN_ES256 = 'true';
    delete process.env.JWT_ACCEPT_HS256;
    resetSigningKeyCacheForTests();
    resetKeyCacheForTests();
  };

  beforeEach(() => enableEs256());

  afterAll(() => {
    process.env = savedEnv;
    resetSigningKeyCacheForTests();
    resetKeyCacheForTests();
  });

  it('signs an ES256 token (kid header) that the verifier accepts, aud from the param', async () => {
    const { token } = await service.mint({
      claims: { sub: 'provider:BOBOCA', tournamentId: 't-1' },
      audience: 'score',
      expiresIn: 3600,
    });
    expect(headerOf(token)).toMatchObject({ alg: 'ES256', kid: KID });
    const payload = await verifyJwt<{ sub: string; aud: string; tournamentId: string }>(jwt, token);
    expect(payload).toMatchObject({ sub: 'provider:BOBOCA', aud: 'score', tournamentId: 't-1' });
  });

  it.each(['score', 'provider', 'admin'])('accepts the allow-listed audience %s', async (audience) => {
    const { token } = await service.mint({ claims: { sub: 'u' }, audience, expiresIn: 60 });
    expect(payloadOf(token).aud).toBe(audience);
  });

  it('rejects an audience outside the allow-list', async () => {
    await expect(service.mint({ claims: { sub: 'u' }, audience: 'client', expiresIn: 60 })).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  it('rejects a TTL above the ceiling and at/below the floor', async () => {
    await expect(service.mint({ claims: { sub: 'u' }, audience: 'score', expiresIn: 28801 })).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(service.mint({ claims: { sub: 'u' }, audience: 'score', expiresIn: 0 })).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  it('rejects a non-finite TTL', async () => {
    await expect(
      service.mint({ claims: { sub: 'u' }, audience: 'score', expiresIn: NaN }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('stamps exp from expiresIn (not from a caller-supplied exp)', async () => {
    const before = Math.floor(Date.now() / 1000);
    const { token } = await service.mint({ claims: { sub: 'u' }, audience: 'score', expiresIn: 120 });
    const { iat, exp } = payloadOf(token);
    expect(exp - iat).toBe(120);
    expect(iat).toBeGreaterThanOrEqual(before);
  });

  it('strips caller-supplied reserved claims (aud/iss/exp/iat/nbf/alg/kid)', async () => {
    const { token } = await service.mint({
      claims: {
        sub: 'u',
        aud: 'admin', // must NOT override the audience param
        iss: 'evil-issuer',
        exp: 9999999999,
        iat: 1,
        nbf: 1,
        alg: 'HS256',
        kid: 'attacker-kid',
        tournamentId: 't-9',
      },
      audience: 'score',
      expiresIn: 300,
    });
    // audience param wins; header owns alg/kid; timing owned by the signer.
    expect(headerOf(token)).toMatchObject({ alg: 'ES256', kid: KID });
    const payload = payloadOf(token);
    expect(payload.aud).toBe('score');
    expect(payload.iss).toBeUndefined();
    expect(payload.tournamentId).toBe('t-9');
    expect(payload.exp - payload.iat).toBe(300);
    // A valid signature over the sanitized payload — the forged claims never landed.
    await expect(verifyJwt(jwt, token)).resolves.toMatchObject({ aud: 'score', tournamentId: 't-9' });
  });

  it('rejects non-object claims', async () => {
    await expect(
      service.mint({ claims: null as any, audience: 'score', expiresIn: 60 }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      service.mint({ claims: ['x'] as any, audience: 'score', expiresIn: 60 }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('fails closed (503) when ES256 signing is not enabled — never emits HS256', async () => {
    delete process.env.JWT_SIGN_ES256;
    resetSigningKeyCacheForTests();
    await expect(
      service.mint({ claims: { sub: 'u' }, audience: 'score', expiresIn: 60 }),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});
