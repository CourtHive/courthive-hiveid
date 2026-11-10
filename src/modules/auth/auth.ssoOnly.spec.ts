import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { AuthService } from './auth.service';

/**
 * An SSO-only account (created by a provisioner's `POST /provisioner/users`, no password) can never log in with a
 * password. Pinned here since 2026-11-05: CFS's live-stack spec covered it while CFS served `/auth/login`, and that
 * route now lives only in hiveid.
 */
function make(user: any) {
  const userStorage: any = { findOne: vi.fn(async (email: string) => (email === user.email ? { ...user } : null)) };
  const service = new AuthService(
    new JwtService({ secret: 'test-hs-secret' }),
    {} as any,
    userStorage,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
  );
  return { service };
}

describe('password login for an SSO-only account', () => {
  it('is refused with the SSO message, whatever password is offered', async () => {
    const { service } = make({ userId: 'u1', email: 'sso@x.org', password: '', roles: ['client'] });

    for (const password of ['anything', '']) {
      const attempt = service.signIn('sso@x.org', password);
      await expect(attempt).rejects.toBeInstanceOf(UnauthorizedException);
      await expect(service.signIn('sso@x.org', password)).rejects.toThrow(/SSO/);
    }
  });
});
