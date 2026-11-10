// StorageModule — owns the pg Pool lifecycle (a single writable connection to
// the shared `courthive` DB) and exports the storages the auth authority needs.
// @Global so feature modules don't re-import it. The pool is created on module
// init and drained on shutdown. This is the IdP's connection to the shared core
// DB (see planning/ACCOUNT_MOVE_PHASE2_3_PLAN.md §3).

import { Global, Inject, Module, OnApplicationShutdown } from '@nestjs/common';
import { Pool } from 'pg';

import { PROVISIONER_PROVIDER_STORAGE } from './interfaces/provisioner-provider-storage.interface';
import { USER_PROVISIONER_STORAGE } from './interfaces/user-provisioner-storage.interface';
import { USER_PROVIDER_STORAGE } from './interfaces/user-provider-storage.interface';
import { REFRESH_TOKEN_STORAGE } from './interfaces/refresh-token-storage.interface';
import { AUTH_CODE_STORAGE } from './interfaces/auth-code-storage.interface';
import { PROVIDER_STORAGE } from './interfaces/provider-storage.interface';
import { USER_STORAGE } from './interfaces/user-storage.interface';

import { PostgresProvisionerProviderStorage } from './postgres-provisioner-provider.storage';
import { PostgresUserProvisionerStorage } from './postgres-user-provisioner.storage';
import { PostgresUserProviderStorage } from './postgres-user-provider.storage';
import { PostgresRefreshTokenStorage } from './postgres-refresh-token.storage';
import { PostgresAuthCodeStorage } from './postgres-auth-code.storage';
import { PostgresProviderStorage } from './postgres-provider.storage';
import { PostgresUserStorage } from './postgres-user.storage';
import { attachPoolErrorHandler } from './pool-error-handler';
import { PG_POOL, getPostgresConfig } from './postgres.config';

const STORAGE_PROVIDERS = [
  { provide: USER_STORAGE, useClass: PostgresUserStorage },
  { provide: PROVIDER_STORAGE, useClass: PostgresProviderStorage },
  { provide: USER_PROVIDER_STORAGE, useClass: PostgresUserProviderStorage },
  { provide: USER_PROVISIONER_STORAGE, useClass: PostgresUserProvisionerStorage },
  { provide: PROVISIONER_PROVIDER_STORAGE, useClass: PostgresProvisionerProviderStorage },
  { provide: REFRESH_TOKEN_STORAGE, useClass: PostgresRefreshTokenStorage },
  { provide: AUTH_CODE_STORAGE, useClass: PostgresAuthCodeStorage },
];

@Global()
@Module({
  providers: [
    {
      provide: PG_POOL,
      // attachPoolErrorHandler, not a bare `new Pool(...)`: an idle client that
      // fails (restart, failover, pg_terminate_backend) emits 'error' on the pool,
      // and with no listener Node throws and the service exits. See its header.
      useFactory: () => attachPoolErrorHandler(new Pool(getPostgresConfig()), 'core-db'),
    },
    ...STORAGE_PROVIDERS,
  ],
  exports: [PG_POOL, ...STORAGE_PROVIDERS.map((p) => p.provide)],
})
export class StorageModule implements OnApplicationShutdown {
  constructor(@Inject(PG_POOL) private readonly pool: Pool) {}

  async onApplicationShutdown(): Promise<void> {
    await this.pool.end();
  }
}
