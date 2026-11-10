import { ServiceUnavailableException } from '@nestjs/common';
import { Pool } from 'pg';

import { HealthController } from './health.controller';
import type { Mock } from 'vitest';

function poolMock(query: Mock): Pool {
  return { query } as unknown as Pool;
}

describe('HealthController', () => {
  it('reports liveness on /health', () => {
    const controller = new HealthController(poolMock(vi.fn()));
    // The node block is asserted, not tolerated. NestJS 12 is ESM-only and this
    // service reaches it through `require(esm)`. Node 24 is the ecosystem floor; a
    // host below it is unsupported, and a /health that answered a bare `ok` would
    // look identical on one.
    expect(controller.check()).toEqual({
      status: 'ok',
      service: 'courthive-hiveid',
      node: { version: process.version, minimum: '>=24', satisfied: true },
    });
  });

  it('/health/core-db returns ok when the pool responds', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ '?column?': 1 }] });
    const controller = new HealthController(poolMock(query));
    await expect(controller.coreDb()).resolves.toEqual({ status: 'ok', db: 'courthive' });
    expect(query).toHaveBeenCalledWith('SELECT 1');
  });

  it('/health/core-db fails closed (503) when the pool is unreachable', async () => {
    const query = vi.fn().mockRejectedValue(new Error('connection refused'));
    const controller = new HealthController(poolMock(query));
    await expect(controller.coreDb()).rejects.toBeInstanceOf(ServiceUnavailableException);
  });
});
