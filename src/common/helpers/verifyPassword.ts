import bcrypt from 'bcryptjs';

/**
 * The one password check. A stored password is a bcrypt hash and nothing else: the offered password is never
 * compared with the stored value directly. That comparison accepted the hash itself as a password (anyone who read
 * a users row could log in as its owner), and accepted rows stored in plaintext.
 */
export async function verifyPassword(clearTextPassword: string, storedHash?: string | null): Promise<boolean> {
  if (!clearTextPassword || !storedHash) return false;
  try {
    return await bcrypt.compare(clearTextPassword, storedHash);
  } catch {
    // A stored value bcrypt cannot parse is not a hash, so nothing matches it.
    return false;
  }
}
