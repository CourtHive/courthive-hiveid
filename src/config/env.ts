// Typed environment loader for courthive-hiveid.
//
// The IdP connects to the SHARED `courthive` database (where the `users` table
// lives) via the same PG_* vars competition-factory-server uses — see
// storage/postgres.config.ts. `users` physically stays in `courthive`; the DB
// split to a dedicated auth database is a separate, later item.
//
// Signing/JWT fields are added in the signer increment (this service becomes
// the sole ES256 signer). This foundational increment only needs the port,
// node env, and the database name (for the /health/core-db report).

import 'dotenv/config';

export interface AppEnv {
  port: number;
  nodeEnv: 'development' | 'production' | 'test';
  pgDatabase: string;
}

export function loadEnv(): AppEnv {
  const nodeEnv = (process.env.NODE_ENV ?? 'development') as AppEnv['nodeEnv'];
  const port = Number(process.env.PORT ?? 3140);
  const pgDatabase = process.env.PG_DATABASE ?? 'courthive';

  if (!Number.isFinite(port) || port <= 0) {
    throw new Error(`courthive-hiveid: invalid PORT '${process.env.PORT}'`);
  }

  // The internal /internal/mint signer is service-token guarded (fail-closed per
  // request). In production, refuse to boot without the shared secret so the
  // signer can never be deployed silently open — the operator gets a loud, early
  // failure instead of a route that rejects every mint.
  if (nodeEnv === 'production' && !process.env.HIVEID_SIGNER_TOKEN) {
    throw new Error('courthive-hiveid: HIVEID_SIGNER_TOKEN is required in production (guards /internal/mint)');
  }

  return { port, nodeEnv, pgDatabase };
}
