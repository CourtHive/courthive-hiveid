import bcrypt from 'bcryptjs';

import { verifyPassword } from './verifyPassword';

describe('verifyPassword', () => {
  it('matches only the password that hashes to the stored value', async () => {
    const hash = await bcrypt.hash('secret', 4);
    expect(await verifyPassword('secret', hash)).toBe(true);
    expect(await verifyPassword('wrong', hash)).toBe(false);
    expect(await verifyPassword(hash, hash)).toBe(false);
  });

  it('matches nothing against a stored value that is not a hash, or is missing', async () => {
    expect(await verifyPassword('plain', 'plain')).toBe(false);
    expect(await verifyPassword('', '')).toBe(false);
    expect(await verifyPassword('x', undefined)).toBe(false);
    expect(await verifyPassword('x', '$2a$10$' + 'z'.repeat(53))).toBe(false);
  });
});
