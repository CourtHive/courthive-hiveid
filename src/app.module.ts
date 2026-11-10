// Root module for courthive-hiveid (the HiveID IdP).
//
// StorageModule is @Global — it owns the pg Pool to the shared `courthive` DB
// and exports the storages. JwtModule is registered globally so signJwt /
// verifyJwt resolve a JwtService anywhere. AuthModule owns the login/session/
// admin surface + the global guards; HiveIDModule the public signup/identity
// surface; IdentityModule the contact-email verify (imported via AuthModule).
// The SPLIT tournament-token controllers + provisioner SSO AUTHORIZATION stay on
// CFS; CFS calls the IdP's MintModule (POST /internal/mint) to SIGN them, since
// only the IdP holds the key.

import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { HealthModule } from './modules/health/health.module';
import { JwksModule } from './modules/jwks/jwks.module';
import { HiveIDModule } from './modules/hiveid/hiveid.module';
import { MintModule } from './modules/mint/mint.module';
import { AuthModule } from './modules/auth/auth.module';
import { StorageModule } from './storage/storage.module';
import { ConfigsModule } from './config/config.module';

@Module({
  imports: [
    ConfigsModule,
    JwtModule.register({ global: true, secret: process.env.JWT_SECRET }),
    StorageModule,
    AuthModule,
    HiveIDModule,
    MintModule,
    JwksModule,
    HealthModule,
  ],
})
export class AppModule {}
