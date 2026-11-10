import { Module } from '@nestjs/common';

import { PersonsClientModule } from 'src/modules/persons/persons-client.module';
import { IdentityModule } from 'src/modules/identity/identity.module';
import { EmailModule } from 'src/modules/email/email.module';
import { AuthModule } from 'src/modules/auth/auth.module';
import { HiveIDController } from './hiveid.controller';
import { HiveIDService } from './hiveid.service';

// Public HiveID signup/identity surface. Composes AuthService (session mint) +
// IdentityService (email verify) + EmailService + PersonsClient (canonical
// identity resolve/mint). Storage tokens + ConfigService come from the globals.
@Module({
  imports: [AuthModule, IdentityModule, EmailModule, PersonsClientModule],
  controllers: [HiveIDController],
  providers: [HiveIDService],
})
export class HiveIDModule {}
