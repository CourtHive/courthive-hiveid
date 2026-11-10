import { PostgresUserStorage } from './postgres-user.storage';

// `buildSessionPayload` does `const { password, ...userDetails } = user` and signs
// `userDetails` wholesale, so every field these mappers emit lands in the login
// JWT. That makes the mapper the actual claim contract — hence covering it here.

const BASE_ROW = {
  user_id: 'u1',
  person_id: 'p-canonical',
  email: 'coach@example.edu',
  password: 'hashed',
  provider_id: 'prov1',
  last_selected_provider_id: null,
  must_change_password: false,
  contact_email: null,
  email_verified_at: null,
  roles: ['client'],
  permissions: {},
  data: {},
  standard_given_name: 'Ada',
  standard_family_name: 'Lovelace',
};

function makeStorage(row: any) {
  const pool: any = { query: vi.fn().mockResolvedValue({ rows: row ? [row] : [] }) };
  return { pool, storage: new PostgresUserStorage(pool) };
}

describe('PostgresUserStorage — personId reaches the session payload', () => {
  it.each([
    ['findOne', (s: PostgresUserStorage) => s.findOne('coach@example.edu')],
    ['findByContactEmail', (s: PostgresUserStorage) => s.findByContactEmail('coach@example.edu')],
    ['findByUserId', (s: PostgresUserStorage) => s.findByUserId('u1')],
  ])('%s selects person_id and maps it to personId', async (_label, call) => {
    const { pool, storage } = makeStorage(BASE_ROW);
    const result: any = await call(storage);
    expect(result.personId).toBe('p-canonical');
    // The column must actually be requested — mapping a column the query never
    // selected would silently yield undefined in production.
    expect(pool.query.mock.calls[0][0]).toContain('person_id');
  });

  // The canonical link is the `person_id` COLUMN, written by setPersonLink and
  // validated against courthive-persons. The legacy `data` JSONB is user-editable
  // surface and must never be able to forge or shadow an identity claim.
  it.each([
    ['findOne', (s: PostgresUserStorage) => s.findOne('coach@example.edu')],
    ['findByContactEmail', (s: PostgresUserStorage) => s.findByContactEmail('coach@example.edu')],
    ['findByUserId', (s: PostgresUserStorage) => s.findByUserId('u1')],
  ])('%s: the column wins over a personId planted in the data blob', async (_label, call) => {
    const { storage } = makeStorage({ ...BASE_ROW, data: { personId: 'p-forged-via-json' } });
    const result: any = await call(storage);
    expect(result.personId).toBe('p-canonical');
  });

  it('maps a NULL person_id to undefined so the claim is absent, not present-and-null', async () => {
    const { storage } = makeStorage({ ...BASE_ROW, person_id: null });
    const result: any = await storage.findOne('coach@example.edu');
    expect(result.personId).toBeUndefined();
    expect('personId' in result).toBe(true);
  });

  it('returns null for an unknown user rather than an empty identity', async () => {
    const { storage } = makeStorage(null);
    expect(await storage.findOne('nobody@example.edu')).toBeNull();
  });
});

// Multi-provider: a user's providers are
// user_providers rows. users.provider_id is neither read nor written, so the column can be dropped.
describe('PostgresUserStorage — users.provider_id is retired', () => {
  it('create neither writes provider_id nor stashes providerId in data', async () => {
    const { pool, storage } = makeStorage(null);
    await storage.create({ email: 'a@b.c', password: 'h', providerId: 'p1', roles: ['client'], firstName: 'A' });
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).not.toContain('provider_id');
    expect(params).not.toContain('p1');
    expect(JSON.parse(params[5])).toEqual({ firstName: 'A' });
  });

  it('update neither writes provider_id nor stashes providerId in data', async () => {
    const { pool, storage } = makeStorage(null);
    await storage.update('a@b.c', { password: 'h', providerId: 'p1', roles: [], firstName: 'A' });
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).not.toContain('provider_id');
    expect(params).not.toContain('p1');
    expect(JSON.parse(params[5])).toEqual({ firstName: 'A' });
  });

  it('the finders neither select provider_id nor emit providerId into the session payload', async () => {
    const { pool, storage } = makeStorage(BASE_ROW);
    expect(await storage.findOne('coach@example.edu')).not.toHaveProperty('providerId');
    expect(await storage.findByContactEmail('coach@example.edu')).not.toHaveProperty('providerId');
    expect(await storage.findByUserId('u1')).not.toHaveProperty('providerId');
    await storage.findAll();
    for (const [sql] of pool.query.mock.calls) {
      // `up.provider_id` / `provider_ids` are user_providers; `last_selected_provider_id` is a different column
      expect(sql).not.toMatch(/(^|[^._a-z])(u\.)?provider_id\b(?!s)/);
    }
  });
});
