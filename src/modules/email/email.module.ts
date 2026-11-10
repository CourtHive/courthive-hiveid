// EmailModule — the IdP's own transactional-mail transport (the IdP owns its
// ResendAdapter so auth mail does not depend on another service's uptime).
// Switching vendors is one provider line. ConfigService is global (ConfigsModule).

import { Module } from '@nestjs/common';

import { EMAIL_ADAPTER } from './adapters/email-adapter.interface';
import { ResendAdapter } from './adapters/resend.adapter';
import { EmailService } from './email.service';

@Module({
  providers: [
    {
      provide: EMAIL_ADAPTER,
      useClass: ResendAdapter,
    },
    EmailService,
  ],
  exports: [EmailService],
})
export class EmailModule {}
