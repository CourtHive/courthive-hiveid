import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import bcrypt from 'bcryptjs';

import { audienceMatches } from 'src/common/auth/guards/auth.guard';
import { PROVIDER_SELECTION_PURPOSE } from './helpers/actingProvider';
import { resetSigningKeyCacheForTests } from 'src/common/auth/signJwt';
import { PROVISIONER } from 'src/common/constants/roles';
import { AuthService } from './auth.service';

/**
 * TWO-STEP LOGIN FOR A USER WITH MORE THAN ONE PROVIDER.
 *
 * Login answers with the user's providers and a selection token; `select-provider` returns the session for
 * the chosen one. The selection token must be useless anywhere else, and a refreshed session must keep the
 * provider that was chosen.
 */

const PASSWORD = 'correct horse';
const PROVIDERS: Record<string, any> = {
  club: { organisationId: 'club', organisationName: 'Club', organisationAbbreviation: 'CLB' },
  league: { organisationId: 'league', organisationName: 'League', organisationAbbreviation: 'LGE' },
  boca: { organisationId: 'boca', organisationName: 'Boca', organisationAbbreviation: 'BOC' },
  arena: { organisationId: 'arena', organisationName: 'Arena', organisationAbbreviation: 'ARN' },
};

function make(options: { associations?: string[]; lastSelected?: string | null; managed?: string[] } = {}) {
  const associations = options.associations ?? ['club', 'league'];
  // providers the user's provisioner manages: only read for a user holding the provisioner role
  const managed = options.managed;
  const user = {
    userId: 'u1',
    email: 'director@x.org',
    password: bcrypt.hashSync(PASSWORD, 4),
    roles: managed ? ['client', PROVISIONER] : ['client'],
    providerId: 'club', // the legacy home column: it must NOT decide anything for a multi-provider user
    lastSelectedProviderId: options.lastSelected ?? null,
  };
  const userStorage: any = {
    findOne: vi.fn(async (email: string) => (email === user.email ? { ...user } : null)),
    findByUserId: vi.fn(async (id: string) => (id === user.userId ? { ...user } : null)),
    updateLastAccess: vi.fn().mockResolvedValue(undefined),
    updateLastSelectedProviderId: vi.fn().mockResolvedValue({ success: true }),
  };
  const userProviderStorage: any = {
    findByUserIdEnriched: vi.fn(async () =>
      associations.map((providerId) => ({
        providerId,
        providerRole: 'PROVIDER_ADMIN',
        organisationName: PROVIDERS[providerId]?.organisationName,
        organisationAbbreviation: PROVIDERS[providerId]?.organisationAbbreviation,
      })),
    ),
  };
  const providerStorage: any = {
    getProvider: vi.fn(async (id: string) => PROVIDERS[id] ?? null),
    updateLastAccess: vi.fn().mockResolvedValue(undefined),
  };
  let refreshRow: any;
  const refreshTokenService: any = {
    issue: vi.fn(async (_userId: string, _email: string, _ua?: string, acting?: string | null) => {
      refreshRow = { actingProviderId: acting ?? null };
      return 'rtok_issued';
    }),
    rotate: vi.fn(async () => ({
      userId: user.userId,
      email: user.email,
      refreshToken: 'rtok_next',
      actingProviderId: refreshRow?.actingProviderId ?? null,
    })),
  };
  const jwt = new JwtService({ secret: 'test-hs-secret' });
  const service = new AuthService(
    jwt,
    providerStorage,
    userStorage,
    { findProvisionerIdsByUser: vi.fn().mockResolvedValue(managed ? ['prov1'] : []) } as any,
    userProviderStorage,
    { findByProvisioner: vi.fn(async () => (managed ?? []).map((providerId) => ({ providerId }))) } as any,
    refreshTokenService,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
    {} as any,
  );
  return {
    service,
    jwt,
    user,
    userStorage,
    refreshTokenService,
    setAssociations: (ids: string[]) => associations.splice(0, associations.length, ...ids),
  };
}

describe('two-step login', () => {
  const savedEnv = { ...process.env };
  beforeAll(() => {
    delete process.env.JWT_SIGN_ES256;
    resetSigningKeyCacheForTests();
  });
  afterAll(() => {
    process.env = savedEnv;
    resetSigningKeyCacheForTests();
  });

  it('a user with several providers gets their providers and a selection token, NOT a session', async () => {
    const { service } = make({ lastSelected: 'league' });
    const result: any = await service.signIn('director@x.org', PASSWORD);
    expect(result.providerSelectionRequired).toBe(true);
    expect(result.token).toBeUndefined();
    expect(result.refreshToken).toBeUndefined();
    expect(result.providers.map((p: any) => p.providerId)).toEqual(['club', 'league']);
    // preselected in the picker
    expect(result.lastSelectedProviderId).toBe('league');
  });

  it('the selection token cannot pass for a user anywhere else', async () => {
    const { service, jwt } = make();
    const { selectionToken }: any = await service.signIn('director@x.org', PASSWORD);
    const claims: any = jwt.decode(selectionToken);
    expect(claims).toMatchObject({
      purpose: PROVIDER_SELECTION_PURPOSE,
      aud: 'provider-selection',
      selectingUserId: 'u1',
    });
    for (const claim of ['userId', 'sub', 'email', 'roles', 'providerId', 'providerIds'])
      expect(claims[claim]).toBeUndefined();
    // an admin route (the default audience) refuses it; only select-provider declares this audience
    expect(audienceMatches(claims.aud, ['admin'])).toBe(false);
    expect(audienceMatches(claims.aud, ['provider-selection', 'admin'])).toBe(true);
  });

  it('selecting a provider returns the session scoped to it, and remembers the choice', async () => {
    const { service, jwt, userStorage, refreshTokenService } = make();
    const { selectionToken }: any = await service.signIn('director@x.org', PASSWORD);
    const session: any = await service.selectProvider('league', jwt.decode(selectionToken));
    const claims: any = jwt.decode(session.token);
    expect(claims.providerId).toBe('league');
    expect(claims.provider.organisationId).toBe('league');
    expect(claims.providerSelectionRequired).toBe(false);
    expect(claims.aud).toBe('admin');
    expect(userStorage.updateLastSelectedProviderId).toHaveBeenCalledWith('director@x.org', 'league');
    // pinned to the refresh token
    expect(refreshTokenService.issue.mock.calls.at(-1)[3]).toBe('league');
  });

  it('refuses a provider the user is not associated with', async () => {
    const { service, jwt } = make();
    const { selectionToken }: any = await service.signIn('director@x.org', PASSWORD);
    await expect(service.selectProvider('elsewhere', jwt.decode(selectionToken))).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('refuses any other purpose token (first-login, password reset)', async () => {
    const { service } = make();
    await expect(
      service.selectProvider('club', { purpose: 'password-reset', email: 'director@x.org' }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('switching with a full session token issues a session for the new provider', async () => {
    const { service, jwt } = make();
    const first: any = await service.selectProvider('club', { userId: 'u1' });
    const switched: any = await service.selectProvider('league', jwt.decode(first.token));
    expect((jwt.decode(switched.token) as any).providerId).toBe('league');
  });

  it('a refreshed session keeps the chosen provider; a removed association ends it', async () => {
    const { service, jwt, setAssociations } = make();
    await service.selectProvider('league', { userId: 'u1' });
    const refreshed: any = await service.refreshSession('rtok_issued');
    expect((jwt.decode(refreshed.token) as any).providerId).toBe('league');

    setAssociations(['club', 'other']);
    await expect(service.refreshSession('rtok_issued')).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('a single-provider user signs straight in, scoped to their provider, as before', async () => {
    const { service, jwt, refreshTokenService } = make({ associations: ['club'] });
    const result: any = await service.signIn('director@x.org', PASSWORD);
    expect(result.providerSelectionRequired).toBeUndefined();
    expect((jwt.decode(result.token) as any).providerId).toBe('club');
    // nothing pinned: their session rebuilds exactly as before on refresh
    expect(refreshTokenService.issue.mock.calls.at(-1)[3]).toBeUndefined();
  });

  describe('providers reached through a provisioner', () => {
    it('the picker lists them after the direct ones, each marked, with no duplicate', async () => {
      // 'league' is both a direct association and managed: it appears once, as the direct one
      const { service } = make({ managed: ['league', 'boca', 'arena'] });
      const result: any = await service.signIn('director@x.org', PASSWORD);
      expect(result.providerSelectionRequired).toBe(true);
      expect(result.providers.map((p: any) => [p.providerId, !!p.viaProvisioner])).toEqual([
        ['club', false],
        ['league', false],
        ['boca', true],
        ['arena', true],
      ]);
      expect(result.providers[2]).toMatchObject({ organisationName: 'Boca', organisationAbbreviation: 'BOC' });
    });

    it('one of them can be chosen, and the choice is remembered for the next picker', async () => {
      const { service, jwt, userStorage, user } = make({ managed: ['boca'] });
      const { selectionToken }: any = await service.signIn('director@x.org', PASSWORD);
      const session: any = await service.selectProvider('boca', jwt.decode(selectionToken));
      expect((jwt.decode(session.token) as any).providerId).toBe('boca');
      expect(userStorage.updateLastSelectedProviderId).toHaveBeenCalledWith(user.email, 'boca');

      // the remembered pick survives the next login instead of being dropped as "not an association"
      const again = make({ managed: ['boca'], lastSelected: 'boca' });
      const next: any = await again.service.signIn('director@x.org', PASSWORD);
      expect(next.lastSelectedProviderId).toBe('boca');
    });

    it('a remembered pick no longer reachable is dropped', async () => {
      const { service } = make({ managed: ['arena'], lastSelected: 'boca' });
      const result: any = await service.signIn('director@x.org', PASSWORD);
      expect(result.lastSelectedProviderId).toBeNull();
    });

    it('a session that has not chosen (account verification) carries the same list for the client to render', async () => {
      const { service, user } = make({ managed: ['boca'] });
      const payload: any = await service.buildSessionPayload({ ...user });
      expect(payload.providerSelectionRequired).toBe(true);
      expect(payload.choosableProviders.map((p: any) => p.providerId)).toEqual(['club', 'league', 'boca']);
      // the direct associations keep their meaning: permissions read them, so nothing inherited is added there
      expect(payload.providerAssociations.map((p: any) => p.providerId)).toEqual(['club', 'league']);
    });

    it('WHEN the picker appears is unchanged: one direct association still signs straight in', async () => {
      // the headless-client case: a password login must keep answering with a session, not a selection token
      const { service, jwt } = make({ associations: ['club'], managed: ['boca', 'arena'] });
      const result: any = await service.signIn('director@x.org', PASSWORD);
      expect(result.providerSelectionRequired).toBeUndefined();
      expect(result.token).toBeDefined();
      const claims: any = jwt.decode(result.token);
      expect(claims.providerId).toBe('club');
      // the list only rides on a session that has not chosen
      expect(claims.choosableProviders).toBeUndefined();
    });
  });
});
