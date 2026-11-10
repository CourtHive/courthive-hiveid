import { Module } from '@nestjs/common';

import { EmailModule } from 'src/modules/email/email.module';
import { AuditModule } from 'src/modules/audit/audit.module';
import { IdentityController } from './identity.controller';
import { IdentityService } from './identity.service';

// Contact-email identity surface: set/verify the recovery mailbox distinct from
// the login identifier. JwtService (global) + ConfigService (global) + USER_STORAGE
// (@Global StorageModule) resolve without importing them here.
@Module({
  imports: [EmailModule, AuditModule],
  controllers: [IdentityController],
  providers: [IdentityService],
  exports: [IdentityService],
})
export class IdentityModule {}
