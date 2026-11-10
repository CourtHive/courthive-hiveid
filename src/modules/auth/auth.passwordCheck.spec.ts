import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import bcrypt from 'bcryptjs';

import { AuthService } from './auth.service';

/**
 * A stored password is a bcrypt hash, and the only way in is the password that hashes to it. Until 2026-11-05 the
 * check also accepted `stored === offered`, so the stored hash itself logged its owner in, and the create paths
 * stored plaintext that only that comparison could match.
 */
const SUPER_ADMIN_EDITOR = { userContext: { isSuperAdmin: true } as any };

function make(rows: any[] = []) {
  const users = new Map<string, any>(rows.map((row) => [row.email, { ...row }]));
  const userStorage: any = {
    findOne: vi.fn(async (email: string) => (users.has(email) ? { ...users.get(email) } : null)),
    create: vi.fn(async (user: any) => void users.set(user.email, { ...user, userId: `id-${user.email}` })),
    update: vi.fn(async (email: string, user: any) => void users.set(email, { ...user })),
  };
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
  return { service, users };
}

// mustChangePassword stops signIn at the limited token, so a match is visible without the session machinery.
const forcedChangeUser = (email: string, password: string) => ({ email, password, mustChangePassword: true });

describe('password login', () => {
  it('accepts the password that hashes to the stored value', async () => {
    const hash = await bcrypt.hash('correct horse', 4);
    const { service } = make([forcedChangeUser('a@x.org', hash)]);

    const result: any = await service.signIn('a@x.org', 'correct horse');
    expect(result.mustChangePassword).toBe(true);
  });

  it('refuses the stored hash itself offered as the password', async () => {
    const hash = await bcrypt.hash('correct horse', 4);
    const { service } = make([forcedChangeUser('a@x.org', hash)]);

    await expect(service.signIn('a@x.org', hash)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('refuses a row whose stored password is plaintext, even when the plaintext is offered', async () => {
    const { service } = make([forcedChangeUser('a@x.org', 'plain-secret')]);

    await expect(service.signIn('a@x.org', 'plain-secret')).rejects.toBeInstanceOf(UnauthorizedException);
  });
});

describe('admin-created account', () => {
  it('stores a bcrypt hash of the password it returns, and the returned password logs in', async () => {
    const { service, users } = make();

    const created: any = await service.adminCreateUser({ email: 'new@x.org', password: 'given-pass' }, SUPER_ADMIN_EDITOR);

    const stored = users.get('new@x.org').password;
    expect(stored).not.toBe('given-pass');
    expect(await bcrypt.compare('given-pass', stored)).toBe(true);
    expect(created.password).toBe('given-pass');
    const login: any = await service.signIn('new@x.org', created.password);
    expect(login.mustChangePassword).toBe(true);
  });

  it('hashes the generated password when none is supplied', async () => {
    const { service, users } = make();

    const created: any = await service.adminCreateUser({ email: 'gen@x.org' }, SUPER_ADMIN_EDITOR);

    expect(await bcrypt.compare(created.password, users.get('gen@x.org').password)).toBe(true);
  });
});

describe('/auth/modify', () => {
  it('never writes a password or clears the forced change', async () => {
    const hash = await bcrypt.hash('original', 4);
    const { service, users } = make([{ ...forcedChangeUser('m@x.org', hash), firstName: 'Old' }]);

    await service.modifyUser(
      { email: 'm@x.org', firstName: 'New', password: 'attacker-chosen', mustChangePassword: false },
      SUPER_ADMIN_EDITOR,
    );

    const row = users.get('m@x.org');
    expect(row.firstName).toBe('New');
    expect(row.password).toBe(hash);
    expect(row.mustChangePassword).toBe(true);
  });
});
