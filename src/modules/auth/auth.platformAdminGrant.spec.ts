import { ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { AuthService } from './auth.service';

/**
 * `admin` ("Platform admin") opens operator surfaces across every provider, so only a super-admin may grant
 * it (CA, 2026-11-12). The create path had no grant check at all until then: a provider admin could create an
 * account holding `superadmin`.
 */
const PROVIDER_ID = 'prov-P';
const PROVIDER_ADMIN_EDITOR = {
  userContext: { isSuperAdmin: false, providerRoles: { [PROVIDER_ID]: 'PROVIDER_ADMIN' } } as any,
};
const SUPER_ADMIN_EDITOR = { userContext: { isSuperAdmin: true } as any };

function make(rows: any[] = []) {
  const users = new Map<string, any>(rows.map((row) => [row.email, { ...row }]));
  const userStorage: any = {
    findOne: vi.fn(async (email: string) => (users.has(email) ? { ...users.get(email) } : null)),
    create: vi.fn(async (user: any) => void users.set(user.email, { ...user, userId: `id-${user.email}` })),
    update: vi.fn(async (email: string, user: any) => void users.set(email, { ...user })),
  };
  const userProviderStorage: any = {
    findByUserId: vi.fn(async () => [{ providerId: PROVIDER_ID, providerRole: 'DIRECTOR' }]),
    upsert: vi.fn(async () => undefined),
  };
  const service = new AuthService(
    new JwtService({ secret: 'test-hs-secret' }),
    {} as any,
    userStorage,
    {} as any,
    userProviderStorage,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
  );
  return { service, users, userStorage };
}

describe('granting restricted global roles', () => {
  it.each(['admin', 'superadmin', 'provisioner', 'developer'])(
    'a provider admin cannot create an account holding %s',
    async (role) => {
      const { service, userStorage } = make();

      await expect(
        service.adminCreateUser(
          { email: 'new@x.org', providerId: PROVIDER_ID, roles: ['client', role] },
          PROVIDER_ADMIN_EDITOR,
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
      expect(userStorage.create).not.toHaveBeenCalled();
    },
  );

  it('a provider admin can still create an account with ordinary roles', async () => {
    const { service, users } = make();

    const created: any = await service.adminCreateUser(
      { email: 'new@x.org', providerId: PROVIDER_ID, roles: ['client', 'director', 'score'] },
      PROVIDER_ADMIN_EDITOR,
    );

    expect(created.success).toBe(true);
    expect(users.get('new@x.org').roles).toEqual(['client', 'director', 'score']);
  });

  it('a super-admin may create a Platform admin', async () => {
    const { service, users } = make();

    const created: any = await service.adminCreateUser({ email: 'ops@x.org', roles: ['admin'] }, SUPER_ADMIN_EDITOR);

    expect(created.success).toBe(true);
    expect(users.get('ops@x.org').roles).toEqual(['admin']);
  });

  it('a provider admin cannot add Platform admin to an existing account', async () => {
    const { service, users } = make([{ email: 'm@x.org', userId: 'u-m', roles: ['client'] }]);

    await expect(
      service.modifyUser({ email: 'm@x.org', roles: ['client', 'admin'] }, PROVIDER_ADMIN_EDITOR),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(users.get('m@x.org').roles).toEqual(['client']);
  });

  it('a provider admin may still REMOVE Platform admin from an account', async () => {
    const { service, users } = make([{ email: 'm@x.org', userId: 'u-m', roles: ['client', 'admin'] }]);

    await service.modifyUser({ email: 'm@x.org', roles: ['client'] }, PROVIDER_ADMIN_EDITOR);

    expect(users.get('m@x.org').roles).toEqual(['client']);
  });
});
