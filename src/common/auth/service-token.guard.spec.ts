import { ExecutionContext, UnauthorizedException } from '@nestjs/common';

import { ServiceTokenGuard } from './service-token.guard';

function ctxWith(headers: Record<string, unknown>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers }) }),
  } as unknown as ExecutionContext;
}

describe('ServiceTokenGuard (hiveid /internal/mint)', () => {
  const guard = new ServiceTokenGuard();
  const savedEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it('fails closed when HIVEID_SIGNER_TOKEN is unset (empty secret never opens the route)', () => {
    delete process.env.HIVEID_SIGNER_TOKEN;
    expect(() => guard.canActivate(ctxWith({ 'x-service-token': 'anything' }))).toThrow(UnauthorizedException);
  });

  it('rejects a missing x-service-token header', () => {
    process.env.HIVEID_SIGNER_TOKEN = 'secret-abc';
    expect(() => guard.canActivate(ctxWith({}))).toThrow(UnauthorizedException);
  });

  it('rejects a wrong token', () => {
    process.env.HIVEID_SIGNER_TOKEN = 'secret-abc';
    expect(() => guard.canActivate(ctxWith({ 'x-service-token': 'secret-xyz' }))).toThrow(UnauthorizedException);
  });

  it('rejects a token of a different length (constant-time compare guards)', () => {
    process.env.HIVEID_SIGNER_TOKEN = 'secret-abc';
    expect(() => guard.canActivate(ctxWith({ 'x-service-token': 'secret-abcd' }))).toThrow(UnauthorizedException);
  });

  it('admits the correct token', () => {
    process.env.HIVEID_SIGNER_TOKEN = 'secret-abc';
    expect(guard.canActivate(ctxWith({ 'x-service-token': 'secret-abc' }))).toBe(true);
  });
});
