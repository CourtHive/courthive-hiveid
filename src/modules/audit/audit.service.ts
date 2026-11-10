import { Injectable, Logger } from '@nestjs/common';

/**
 * Minimal audit sink for auth events. The IdP's account move needs an audit
 * trail for password-reset / contact-email changes; this log-based sink is the
 * interim (CFS writes to an audit table). A durable audit table for the IdP is
 * a follow-up.
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  async recordPasswordReset(params: {
    targetUserId: string;
    targetEmail?: string;
    flow: 'token-reset' | 'first-login' | 'admin-reset' | 'self-change';
    actorUserId?: string;
    actorEmail?: string;
  }): Promise<void> {
    const { targetUserId, targetEmail, flow, actorUserId, actorEmail } = params;
    this.logger.log(
      `audit password-reset flow=${flow} target=${targetEmail ?? targetUserId} actor=${actorEmail ?? actorUserId ?? 'self'}`,
    );
  }

  async recordContactEmailChanged(params: {
    targetUserId: string;
    targetEmail?: string;
    actorUserId?: string;
    actorEmail?: string;
    oldContactEmail?: string | null;
    newContactEmail?: string | null;
    source?: string;
  }): Promise<void> {
    const { targetUserId, targetEmail, newContactEmail, source } = params;
    this.logger.log(
      `audit contact-email-changed target=${targetEmail ?? targetUserId} new=${newContactEmail ?? ''} source=${source ?? ''}`,
    );
  }

  async recordContactEmailVerified(params: {
    targetUserId: string;
    targetEmail?: string;
    contactEmail: string;
  }): Promise<void> {
    const { targetUserId, targetEmail, contactEmail } = params;
    this.logger.log(`audit contact-email-verified target=${targetEmail ?? targetUserId} contact=${contactEmail}`);
  }
}
