import { Controller, Get, Inject, ServiceUnavailableException } from '@nestjs/common';
import { Pool } from 'pg';

import { Public } from 'src/common/auth/decorators/public.decorator';
import { PG_POOL } from '../../storage/postgres.config';
import { checkNodeFloor } from './node-floor';
import { loadEnv } from '../../config/env';

@Public()
@Controller('health')
export class HealthController {
  constructor(@Inject(PG_POOL) private readonly pool: Pool) {}

  @Get()
  check() {
    // The node floor is reported, not assumed. NestJS 12 is ESM-only and this
    // service is CommonJS, so it loads Nest through `require(esm)`; the floor is
    // Node 24, the ecosystem minimum. A check that answered a bare "ok" would say the same
    // thing on a host that cannot import Nest at all, which is the failure this
    // field exists to make visible. See node-floor.ts.
    const node = checkNodeFloor();
    return { status: node.satisfied ? 'ok' : 'degraded', service: 'courthive-hiveid', node };
  }

  // Liveness of the IdP's connection to the shared `courthive` DB. Fail-closed
  // (503) so a can't-reach-core-DB condition is loud and monitorable rather
  // than silently degrading auth.
  @Get('core-db')
  async coreDb() {
    const { pgDatabase } = loadEnv();
    try {
      await this.pool.query('SELECT 1');
      return { status: 'ok', db: pgDatabase };
    } catch (err) {
      throw new ServiceUnavailableException({
        status: 'error',
        db: pgDatabase,
        message: err instanceof Error ? err.message : 'core-db unreachable',
      });
    }
  }
}
