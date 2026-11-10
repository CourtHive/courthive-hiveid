#!/usr/bin/env node
/**
 * Hash every users.password still stored as plaintext.
 *
 * Until 2026-11-05 two create paths (admin-create-user, HiveID signup) stored the password as given, and login
 * accepted `stored === offered` to match them. Login is now bcrypt-only, so a row left in plaintext can no longer
 * log in. Hashing the stored value in place keeps the same password working: bcrypt(plaintext) matches it.
 *
 * Safe with either hiveid build running: the old login accepts bcrypt rows as well. Run it before deploying the
 * bcrypt-only build, and once more after, to catch a row the old build created in between. Idempotent.
 *
 *   node scripts/hash-plaintext-passwords.mjs            dry run: counts, and lists the affected emails
 *   node scripts/hash-plaintext-passwords.mjs --apply    hash them, in one transaction
 *
 * Reads PG_HOST / PG_PORT / PG_USER / PG_PASSWORD / PG_DATABASE from the environment or ./.env. Never prints a
 * password or a hash.
 */
import 'dotenv/config';
import bcrypt from 'bcryptjs';
import pg from 'pg';

const BCRYPT = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;
const apply = process.argv.includes('--apply');

const pool = new pg.Pool({
  host: process.env.PG_HOST || 'localhost',
  port: Number(process.env.PG_PORT) || 5432,
  user: process.env.PG_USER || 'courthive',
  password: process.env.PG_PASSWORD || '',
  database: process.env.PG_DATABASE || 'courthive',
});

async function main() {
  const client = await pool.connect();
  try {
    const { rows } = await client.query(`SELECT user_id, email, password FROM users`);
    const empty = rows.filter((row) => !row.password).length;
    const hashed = rows.filter((row) => row.password && BCRYPT.test(row.password)).length;
    const plaintext = rows.filter((row) => row.password && !BCRYPT.test(row.password));

    console.log(`users: ${rows.length}  bcrypt: ${hashed}  empty (SSO-only): ${empty}  plaintext: ${plaintext.length}`);
    for (const row of plaintext) console.log(`  plaintext: ${row.email}`);
    if (!plaintext.length) return;
    if (!apply) {
      console.log('\nDry run. Re-run with --apply to hash these rows.');
      return;
    }

    await client.query('BEGIN');
    let updated = 0;
    for (const row of plaintext) {
      const hash = await bcrypt.hash(row.password, 10);
      // Matches on the old value too, so a password changed since the SELECT is left alone.
      const result = await client.query(
        `UPDATE users SET password = $2, updated_at = NOW() WHERE user_id = $1 AND password = $3`,
        [row.user_id, hash, row.password],
      );
      updated += result.rowCount;
    }
    await client.query('COMMIT');
    console.log(`\nHashed ${updated} of ${plaintext.length}.`);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
