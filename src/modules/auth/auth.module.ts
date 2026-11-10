import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';

import { RefreshTokenService } from 'src/services/refresh-token.service';
import { AuthGuard } from 'src/common/auth/guards/auth.guard';
import { RolesGuard } from 'src/common/auth/guards/role.guard';
import { EmailModule } from 'src/modules/email/email.module';
import { AuditModule } from 'src/modules/audit/audit.module';
import { IdentityModule } from 'src/modules/identity/identity.module';
import { AuthMiddleware } from './auth.middleware';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

// The auth authority module. Registers the global AuthGuard + RolesGuard
// (APP_GUARD) so every route is authed unless marked @Public, and the
// AuthMiddleware that hydrates req.user / req.userContext for @UserCtx. Storage
// tokens come from the @Global StorageModule; JwtService from the global
// JwtModule (app.module).
@Module({
  imports: [EmailModule, AuditModule, IdentityModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    RefreshTokenService,
    AuthMiddleware,
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
  exports: [AuthService],
})
export class AuthModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(AuthMiddleware).forRoutes('*');
  }
}
