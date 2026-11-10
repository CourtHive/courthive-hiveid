import { ADMIN, PROVISIONER, SUPER_ADMIN } from 'src/common/constants/roles';

import { buildUserContext } from './buildUserContext';

const providerStore = (rows: any[]) => ({ findByUserId: vi.fn().mockResolvedValue(rows) }) as any;

describe('buildUserContext', () => {
  it('hydrates provider roles from user_providers', async () => {
    const ctx = await buildUserContext(
      { userId: 'u1', email: 'a@b.c', roles: [] },
      { userProviderStorage: providerStore([{ providerId: 'P1', providerRole: 'PROVIDER_ADMIN' }]) },
    );
    expect(ctx.providerRoles).toEqual({ P1: 'PROVIDER_ADMIN' });
    expect(ctx.providerIds).toEqual(['P1']);
    expect(ctx.isSuperAdmin).toBe(false);
  });

  it('flags super admin from global roles', async () => {
    const ctx = await buildUserContext(
      { userId: 'u1', email: 'a@b.c', roles: [SUPER_ADMIN] },
      { userProviderStorage: providerStore([]) },
    );
    expect(ctx.isSuperAdmin).toBe(true);
  });

  // The legacy shim (retired 2026-10-07) derived provider roles from users.provider_id. Rows are now the only source.
  it('does not promote the deprecated admin role at the home provider', async () => {
    const ctx = await buildUserContext(
      { userId: 'u1', email: 'a@b.c', roles: [ADMIN], providerId: 'HOME' },
      { userProviderStorage: providerStore([{ providerId: 'HOME', providerRole: 'DIRECTOR' }]) },
    );
    expect(ctx.providerRoles).toEqual({ HOME: 'DIRECTOR' });
  });

  it('grants nothing at the home provider when there are no rows', async () => {
    const ctx = await buildUserContext(
      { userId: 'u1', email: 'a@b.c', roles: [ADMIN], providerId: 'HOME' },
      { userProviderStorage: providerStore([]) },
    );
    expect(ctx.providerRoles).toEqual({});
    expect(ctx.providerIds).toEqual([]);
  });

  it('fails closed when the user_providers lookup throws', async () => {
    const ctx = await buildUserContext(
      { userId: 'u1', email: 'a@b.c', roles: [], providerId: 'HOME' },
      { userProviderStorage: { findByUserId: vi.fn().mockRejectedValue(new Error('no table')) } as any },
    );
    expect(ctx.providerRoles).toEqual({});
  });

  it('inherits provisioner provider visibility when both storages are supplied', async () => {
    const ctx = await buildUserContext(
      { userId: 'u1', email: 'a@b.c', roles: [PROVISIONER] },
      {
        userProviderStorage: providerStore([]),
        userProvisionerStorage: { findProvisionerIdsByUser: vi.fn().mockResolvedValue(['prov1']) } as any,
        provisionerProviderStorage: {
          findByProvisioner: vi.fn().mockResolvedValue([{ providerId: 'PX' }, { providerId: 'PY' }]),
        } as any,
      },
    );
    expect((ctx.provisionerProviderIds ?? []).sort()).toEqual(['PX', 'PY']);
  });
});
