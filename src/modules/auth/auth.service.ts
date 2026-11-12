import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { computeEffectiveConfig } from '@courthive/provider-config';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';

import { assertProviderEditor } from 'src/common/helpers/assertProviderEditor';
import { createUniqueKey } from 'src/common/auth/helpers/createUniqueKey';
import { verifyPassword } from 'src/common/helpers/verifyPassword';
import { hashPassword } from 'src/common/helpers/hashPassword';
import { IdentityService } from 'src/modules/identity/identity.service';
import { EmailService } from 'src/modules/email/email.service';
import { AuditService } from 'src/modules/audit/audit.service';

// constants and interfaces
import { SUCCESS } from 'src/common/constants/app';
import { PROVISIONER as PROVISIONER_ROLE, SUPER_ADMIN, VALID_GLOBAL_ROLES, VALID_PROVIDER_ROLES } from 'src/common/constants/roles';
import type { UserContext } from 'src/common/auth/decorators/user-context.decorator';
import {
  PROVIDER_STORAGE,
  type IProviderStorage,
  USER_STORAGE,
  type IUserStorage,
  USER_PROVISIONER_STORAGE,
  type IUserProvisionerStorage,
  USER_PROVIDER_STORAGE,
  type IUserProviderStorage,
  PROVISIONER_PROVIDER_STORAGE,
  type IProvisionerProviderStorage,
  AUTH_CODE_STORAGE,
  type IAuthCodeStorage,
} from 'src/storage/interfaces';
import { signJwt } from 'src/common/auth/signJwt';
import { verifyJwt } from 'src/common/auth/verifyJwt';
import { RefreshTokenService } from 'src/services/refresh-token.service';
import {
  PROVIDER_SELECTION_AUDIENCE,
  PROVIDER_SELECTION_PURPOSE,
  PROVIDER_SELECTION_TTL,
  resolveActingProviderId,
} from './helpers/actingProvider';

// Access-token (session JWT) lifetime. Short because TMX silently refreshes it
// via POST /auth/refresh using a long-lived rotating refresh token. Both the
// password-login path (signIn) and SSO handoff use this value.
export const ACCESS_TOKEN_TTL = '4h';
export type AudienceClaimValue = 'admin' | 'hiveid' | 'score' | 'provider-selection';

const PASSWORD_RESET_TOKEN_TTL = '1h';
const PASSWORD_RESET_PURPOSE = 'password-reset';

// Magic-link login codes are short-lived + single-use. 15 minutes is long
// enough to receive the email and click, short enough to bound a compromised inbox.
const MAGIC_LINK_TTL_MINUTES = 15;
const MAGIC_LINK_TTL_MS = MAGIC_LINK_TTL_MINUTES * 60 * 1000;
const MAGIC_LINK_PREFIX = 'mlk_';

const ADMIN_ONBOARD_TOKEN_TTL = '7d';

// Conservative RFC-shaped email check — decides whether an admin-supplied
// contact_email is plausible enough to attempt delivery.
const EMAIL_REGEX = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;

const ALLOWED_ROLE_SET = new Set([...VALID_GLOBAL_ROLES, ...VALID_PROVIDER_ROLES, 'admin', 'official', 'director']);

// Global roles a non-SUPER_ADMIN editor may not GRANT, via modifyUser or adminCreateUser. Removing
// them is allowed; only escalation is gated. `admin` ("Platform admin") is platform-wide — it opens
// operator surfaces across every provider — so only a super-admin may hand it out (CA, 2026-11-12).
const RESTRICTED_GRANT_ROLES = new Set<string>([SUPER_ADMIN, PROVISIONER_ROLE, 'developer', 'admin']);

function assertNoPrivilegeEscalation(incomingRoles: unknown, currentRoles: unknown): void {
  if (!Array.isArray(incomingRoles)) return;
  const current: string[] = Array.isArray(currentRoles) ? (currentRoles as string[]) : [];
  const escalations = (incomingRoles as string[]).filter(
    (r) => RESTRICTED_GRANT_ROLES.has(r) && !current.includes(r),
  );
  if (escalations.length) {
    throw new ForbiddenException(`Only SUPER_ADMIN may grant role(s): ${escalations.join(', ')}`);
  }
}

/**
 * Parse a short JWT-style duration ('1h', '7d', '30m', '90s', '2w') into
 * minutes for the email-body interpolation. Falls back to 60 if the shape is
 * unrecognised — the email still renders sensibly; the JWT verification uses
 * the original string.
 */
function parseDurationToMinutes(duration: string): number {
  const match = /^(\d+)\s*([smhdw])$/i.exec(duration ?? '');
  if (!match) return 60;
  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  switch (unit) {
    case 's': return Math.max(1, Math.round(value / 60));
    case 'm': return value;
    case 'h': return value * 60;
    case 'd': return value * 60 * 24;
    case 'w': return value * 60 * 24 * 7;
    default:  return 60;
  }
}

/**
 * The HiveID auth authority, ported from competition-factory-server's
 * account/auth.service. Covers sign-in + session build/refresh/logout,
 * last-selected-provider, password reset/change/complete-first-login,
 * magic-link, and admin user management (create / modify / reset / remove /
 * list). Reads `users` from the shared `courthive` DB directly via USER_STORAGE
 * (the CFS dev-mode UsersService is intentionally not ported). NOT ported: the
 * tournament-entangled token mints (tracker/scorer/provider) + provisioner SSO
 * — those stay on CFS and call the IdP to sign (the SPLIT surface).
 */
@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(PROVIDER_STORAGE) private readonly providerStorage: IProviderStorage,
    @Inject(USER_STORAGE) private readonly userStorage: IUserStorage,
    @Inject(USER_PROVISIONER_STORAGE) private readonly userProvisionerStorage: IUserProvisionerStorage,
    @Inject(USER_PROVIDER_STORAGE) private readonly userProviderStorage: IUserProviderStorage,
    @Inject(PROVISIONER_PROVIDER_STORAGE)
    private readonly provisionerProviderStorage: IProvisionerProviderStorage,
    private readonly refreshTokenService: RefreshTokenService,
    @Inject(AUTH_CODE_STORAGE) private readonly authCodeStorage: IAuthCodeStorage,
    private readonly emailService: EmailService,
    private readonly auditService: AuditService,
    private readonly configService: ConfigService,
    private readonly identityService: IdentityService,
  ) {}

  async signIn(email: string, clearTextPassword: string, userAgent?: string) {
    if (!email) throw new UnauthorizedException();
    const user = await this.userStorage.findOne(email);

    // SSO-only users have empty password — reject direct login
    if (user && !user.password) {
      throw new UnauthorizedException('This account uses SSO login. Please log in through your organization.');
    }

    if (!user || !(await verifyPassword(clearTextPassword, user.password))) throw new UnauthorizedException();

    // Admin-assigned passwords gate into a forced-change flow before a full
    // session is issued. Return a short-lived limited token whose sole purpose
    // is to authenticate the /auth/complete-first-login call (a later slice).
    if (user.mustChangePassword) {
      const limitedToken = await signJwt(
        this.jwtService,
        { email: user.email, purpose: 'first-login-password-change' },
        { expiresIn: '5m' },
      );
      return { mustChangePassword: true, limitedToken };
    }

    return this.startSession(user, userAgent);
  }

  /**
   * The one place a credentialed login becomes a session (password, first-login, magic link).
   *
   * A user associated with MORE THAN ONE provider is never placed in one silently: the
   * answer is the list of their providers and a short-lived selection token, and `POST
   * /auth/select-provider` returns the session for the provider they choose. Everyone else gets their
   * session at once, as before.
   */
  async startSession(user: any, userAgent?: string) {
    const userDetails = await this.buildSessionPayload(user);
    if (userDetails.providerSelectionRequired) return this.providerSelection(user, userDetails);
    return this.issueSession(userDetails, userAgent);
  }

  /**
   * The selection answer. The token is good ONLY for `POST /auth/select-provider`: its audience is not
   * `admin` (so every admin route refuses it), it carries a `purpose` (relying parties may refuse any token with one), and
   * it holds no `userId`, `sub`, `email` or `roles`, so no verifier can read it as a user.
   */
  private async providerSelection(user: any, userDetails: any) {
    const selectionToken = await signJwt(
      this.jwtService,
      { purpose: PROVIDER_SELECTION_PURPOSE, aud: PROVIDER_SELECTION_AUDIENCE, selectingUserId: user.userId },
      { expiresIn: PROVIDER_SELECTION_TTL },
    );
    return {
      providerSelectionRequired: true as const,
      providers: userDetails.providerAssociations,
      // preselected in the picker; the user still confirms
      lastSelectedProviderId: userDetails.lastSelectedProviderId ?? null,
      selectionToken,
    };
  }

  /**
   * POST /auth/select-provider — the session for a chosen provider. Called with the selection token after
   * login, or with a full session token to SWITCH provider. The provider must be one the user is associated
   * with, or one their provisioner manages; super-admins may choose any. The choice is remembered as
   * `last_selected_provider_id` (it preselects the next picker) and pinned to the refresh token, so a
   * refreshed session keeps it.
   */
  async selectProvider(providerId: string, caller: any, userAgent?: string) {
    if (!providerId) throw new BadRequestException('providerId is required');
    const fromSelection = caller?.purpose === PROVIDER_SELECTION_PURPOSE;
    // any other purpose token (first-login, password reset) is refused outright
    if (!fromSelection && caller?.purpose) throw new UnauthorizedException();
    const userId = fromSelection ? caller?.selectingUserId : caller?.userId;
    if (!userId) throw new UnauthorizedException();

    const user = await this.userStorage.findByUserId(userId);
    if (!user) throw new UnauthorizedException();

    const userDetails = await this.buildSessionPayload(user, { actingProviderId: providerId });
    if (userDetails.providerId !== providerId) throw new ForbiddenException('Not associated with that provider');

    this.userStorage.updateLastSelectedProviderId(user.email, providerId).catch((err: any) => {
      Logger.warn(
        `selectProvider: remember ${providerId} for ${user.email} failed: ${err?.message ?? err}`,
        AuthService.name,
      );
    });
    userDetails.lastSelectedProviderId = providerId;
    return this.issueSession(userDetails, userAgent, 'admin', providerId);
  }

  /**
   * Build the enriched, password-stripped JWT payload for a fully authenticated
   * user — provider config, provisioner context, and multi-provider
   * associations — and record last-access as a side effect. Shared by signIn
   * and refreshSession so a silently-refreshed access token carries exactly the
   * same claims as the one minted at login.
   */
  async buildSessionPayload(user: any, options?: { actingProviderId?: string | null }): Promise<any> {
     
    const { password, ...userDetails } = user ?? {};
    const email = user.email;

    let associations: Array<{
      providerId: string;
      providerRole: string;
      organisationName?: string;
      organisationAbbreviation?: string;
    }> = [];
    if (user.userId) {
      try {
        const enriched = await this.userProviderStorage.findByUserIdEnriched(user.userId);
        associations = enriched.map((row) => ({
          providerId: row.providerId,
          providerRole: row.providerRole,
          organisationName: row.organisationName,
          organisationAbbreviation: row.organisationAbbreviation,
        }));
      } catch (err) {
        Logger.warn(`Failed to load providerAssociations for ${email}: ${(err as Error).message}`);
      }
    }
    userDetails.providerAssociations = associations;
    userDetails.providerIds = associations.map((a) => a.providerId);
    if (userDetails.lastSelectedProviderId) {
      const stillValid = associations.some((a) => a.providerId === userDetails.lastSelectedProviderId);
      if (!stillValid) userDetails.lastSelectedProviderId = null;
    }

    const isSuperAdmin = (user.roles ?? []).includes(SUPER_ADMIN);

    if (user.userId && user.roles?.includes(PROVISIONER_ROLE)) {
      try {
        const provisionerIds = await this.userProvisionerStorage.findProvisionerIdsByUser(user.userId);
        userDetails.provisionerIds = provisionerIds;
        userDetails.provisionerProviders = await this.loadProvisionerProviders(provisionerIds);
      } catch (err) {
        Logger.warn(`Failed to load provisioner context for ${email}: ${(err as Error).message}`);
        userDetails.provisionerIds = [];
        userDetails.provisionerProviders = [];
      }
    }

    // THE PROVIDER THIS SESSION ACTS FOR. The `providerId` claim means exactly that, and nothing else.
    const actingProviderId = resolveActingProviderId({
      requested: options?.actingProviderId ?? undefined,
      associatedIds: associations.map((a) => a.providerId),
      provisionerProviderIds: (userDetails.provisionerProviders ?? []).map((p: any) => p.providerId),
      isSuperAdmin,
    });
    // `userDetails` spreads the user row, whose `provider_id` column is the legacy home: never let it
    // stand in for a choice the user did not make
    delete userDetails.providerId;
    delete userDetails.provider;
    delete userDetails.activeProviderConfig;
    userDetails.providerSelectionRequired = !actingProviderId && !isSuperAdmin && associations.length > 1;
    if (actingProviderId) {
      userDetails.providerId = actingProviderId;
      const provider = await this.providerStorage.getProvider(actingProviderId);
      userDetails.provider = provider;
      userDetails.activeProviderConfig = computeEffectiveConfig(
        provider?.providerConfigCaps,
        provider?.providerConfigSettings,
      );
    }

    this.userStorage.updateLastAccess(email).catch((err: any) => {
      Logger.warn(`updateLastAccess(user=${email}) failed: ${err?.message ?? err}`, AuthService.name);
    });
    if (actingProviderId && !isSuperAdmin) {
      const providerId = actingProviderId;
      this.providerStorage.updateLastAccess(providerId).catch((err: any) => {
        Logger.warn(`updateLastAccess(provider=${providerId}) failed: ${err?.message ?? err}`, AuthService.name);
      });
    }

    return userDetails;
  }

  /**
   * Mint an access token plus a long-lived rotating refresh token for an
   * already-built session payload. The refresh token's plaintext is returned
   * to the client exactly once; only its hash is persisted.
   */
  async issueSession(
    userDetails: any,
    userAgent?: string,
    aud: AudienceClaimValue | AudienceClaimValue[] = 'admin',
    chosenProviderId?: string,
  ): Promise<{ token: string; refreshToken: string }> {
    const token = await this.signAccessToken(userDetails, aud);
    const userId = userDetails.userId ?? userDetails.user_id ?? userDetails.email;
    // only an explicit CHOICE is pinned: a single-provider or legacy session rebuilds on refresh as before
    const refreshToken = await this.refreshTokenService.issue(userId, userDetails.email, userAgent, chosenProviderId);
    return { token, refreshToken };
  }

  /** Sign a short-lived access token carrying the given audience claim. */
  async signAccessToken(
    payload: any,
    aud: AudienceClaimValue | AudienceClaimValue[] = 'admin',
  ): Promise<string> {
    return signJwt(this.jwtService, { ...payload, aud }, { expiresIn: ACCESS_TOKEN_TTL });
  }

  /**
   * Exchange a valid refresh token for a fresh access token + rotated refresh
   * token. Reuse of an already-rotated token revokes the whole family. The
   * owning user is reloaded so the new access token reflects any role changes.
   */
  async refreshSession(
    presentedRefreshToken: string,
    userAgent?: string,
  ): Promise<{ token: string; refreshToken: string }> {
    const rotated = await this.refreshTokenService.rotate(presentedRefreshToken, userAgent);
    const user = await this.userStorage.findOne(rotated.email);
    if (!user) throw new UnauthorizedException();
    const chosen = rotated.actingProviderId ?? undefined;
    const userDetails = await this.buildSessionPayload(user, { actingProviderId: chosen });
    // the session's provider is no longer theirs (association removed since): sign in again, rather than
    // carry on under a provider chosen for them
    if (chosen && userDetails.providerId !== chosen)
      throw new UnauthorizedException('Provider access changed; sign in again');
    const token = await this.signAccessToken(userDetails, 'admin');
    return { token, refreshToken: rotated.refreshToken };
  }

  /** Revoke a presented refresh token (logout). Idempotent. */
  async logout(presentedRefreshToken: string) {
    await this.refreshTokenService.revoke(presentedRefreshToken);
    return { ...SUCCESS };
  }

  /**
   * Resolve the distinct set of providers a user's provisioners manage, each
   * enriched with organisation name/abbreviation for the TMX provider switcher.
   */
  private async loadProvisionerProviders(
    provisionerIds: string[],
  ): Promise<Array<{ providerId: string; organisationName: string; organisationAbbreviation: string }>> {
    const byProviderId = new Map<
      string,
      { providerId: string; organisationName: string; organisationAbbreviation: string }
    >();
    for (const provisionerId of provisionerIds) {
      const rows = await this.provisionerProviderStorage.findByProvisioner(provisionerId);
      for (const row of rows) {
        if (byProviderId.has(row.providerId)) continue;
        const provider = await this.providerStorage.getProvider(row.providerId);
        if (provider) {
          byProviderId.set(row.providerId, {
            providerId: row.providerId,
            organisationName: provider.organisationName,
            organisationAbbreviation: provider.organisationAbbreviation,
          });
        }
      }
    }
    return Array.from(byProviderId.values());
  }

  /**
   * PATCH /auth/me/last-selected-provider — persist the user's active provider
   * context. Validates `providerId` against `user_providers`; super admins
   * bypass the association check. Pass `null` to clear.
   */
  async updateLastSelectedProvider(
    email: string,
    providerId: string | null,
    options?: { isSuperAdmin?: boolean },
  ) {
    if (!email) return { error: 'Authentication required' };
    if (providerId !== null && !options?.isSuperAdmin) {
      const user = await this.userStorage.findOne(email);
      if (!user?.userId) return { error: 'User not found' };
      const associations = await this.userProviderStorage.findByUserId(user.userId);
      const allowed = associations.some((a) => a.providerId === providerId);
      if (!allowed) return { error: 'Not authorised for that provider' };
    }
    return await this.userStorage.updateLastSelectedProviderId(email, providerId);
  }

  /**
   * Build the password-reset URL placed in the email body. Lands on the
   * admin-client route which extracts the token and POSTs to
   * /auth/reset-password.
   */
  private buildResetUrl(token: string): string {
    const appConfig: any = this.configService.get('app');
    const base = String(appConfig?.baseUrl ?? process.env.APP_BASE_URL ?? '').replace(/\/+$/, '');
    if (!base) {
      throw new Error('APP_BASE_URL is not set; cannot generate password-reset link.');
    }
    return `${base}/admin/#/reset-password/${token}`;
  }

  /** Issue a password-reset JWT and send the matching template. */
  private async issueAndSendResetEmail(
    user: { userId: string; contactEmail: string; firstName?: string },
    opts: { expiresIn: string; template: 'password-reset-request' | 'admin-created-account'; subject: string; tag: string },
  ): Promise<void> {
    const token = await signJwt(
      this.jwtService,
      { userId: user.userId, contactEmail: user.contactEmail, purpose: PASSWORD_RESET_PURPOSE },
      { expiresIn: opts.expiresIn as any },
    );
    const expiresInMinutes = parseDurationToMinutes(opts.expiresIn);
    await this.emailService.sendTemplated({
      to: user.contactEmail,
      subject: opts.subject,
      template: opts.template,
      data: { firstName: user.firstName ?? '', resetUrl: this.buildResetUrl(token), expiresInMinutes },
      tag: opts.tag,
    });
  }

  /**
   * Request a password reset. Enumeration-defensive: always returns
   * `{ ok: true }`; mail is sent only when the contact_email is registered
   * AND verified. Failures inside the send branch are logged and swallowed.
   */
  async forgotPassword(contactEmail: string): Promise<{ ok: true }> {
    const trimmed = (contactEmail ?? '').trim();
    if (!trimmed) return { ok: true };
    try {
      const user = await this.userStorage.findByContactEmail(trimmed);
      if (user && user.emailVerifiedAt && user.userId && user.contactEmail) {
        await this.issueAndSendResetEmail(
          { userId: user.userId, contactEmail: user.contactEmail, firstName: user.firstName },
          {
            expiresIn: PASSWORD_RESET_TOKEN_TTL,
            template: 'password-reset-request',
            subject: 'Reset your CourtHive password',
            tag: 'password-reset',
          },
        );
        Logger.log(`Sent password-reset mail to ${user.contactEmail} for user ${user.userId}`);
      } else {
        Logger.verbose(`forgotPassword: no eligible recipient for "${trimmed}" (verified=${!!user?.emailVerifiedAt})`);
      }
    } catch (err) {
      Logger.warn(`forgotPassword silently swallowed error: ${(err as Error).message}`);
    }
    return { ok: true };
  }

  /**
   * Apply a password-reset token. Verifies the JWT (`purpose: 'password-reset'`),
   * confirms the contact_email still matches (stale-token defense), writes the
   * new hashed password, revokes all sessions, stamps email-verified, and sends
   * a confirmation email.
   */
  async resetPassword(token: string, newPassword: string) {
    if (!token || !newPassword) return { error: 'token and newPassword are required' };
    let claims: any;
    try {
      claims = await verifyJwt(this.jwtService, token);
    } catch {
      throw new UnauthorizedException('Invalid or expired reset link');
    }
    if (claims?.purpose !== PASSWORD_RESET_PURPOSE || !claims?.userId) {
      throw new UnauthorizedException('Token is not a password-reset token');
    }

    const user = await this.userStorage.findByUserId(claims.userId);
    if (!user) throw new UnauthorizedException();

    if (
      claims.contactEmail &&
      String(user.contactEmail ?? '').toLowerCase() !== String(claims.contactEmail).toLowerCase()
    ) {
      throw new ForbiddenException('Contact email has changed since this reset link was issued');
    }

    const hashed = await hashPassword(newPassword);
    await this.userStorage.setPasswordByUserId(user.userId, hashed);

    await this.auditService.recordPasswordReset({
      targetUserId: user.userId,
      targetEmail: user.email,
      flow: 'token-reset',
    });

    this.refreshTokenService.revokeAllForUser(user.userId).catch((err: any) => {
      Logger.warn(`revokeAllForUser(${user.userId}) after reset failed: ${err?.message ?? err}`, AuthService.name);
    });

    if (!user.emailVerifiedAt) {
      try {
        await this.userStorage.markEmailVerified(user.userId);
      } catch (err) {
        Logger.warn(`Failed to stamp email_verified_at after reset for ${user.userId}: ${(err as Error).message}`);
      }
    }

    if (user.contactEmail) {
      this.emailService
        .sendTemplated({
          to: user.contactEmail,
          subject: 'Your CourtHive password was changed',
          template: 'password-reset-confirmation',
          data: { firstName: user.firstName ?? '', changedAt: new Date().toISOString() },
          tag: 'password-reset-confirmation',
        })
        .catch((err) => {
          Logger.warn(`Failed to send password-reset confirmation to ${user.contactEmail}: ${(err as Error).message}`);
        });
    }

    return { ...SUCCESS };
  }

  /**
   * Complete the forced first-login password change. Called after signIn
   * returns `{ mustChangePassword: true, limitedToken }`. Verifies the limited
   * token's `purpose`, writes the new password, clears the flag, and issues a
   * full session via a fresh signIn.
   */
  async completeFirstLogin(limitedToken: string, newPassword: string) {
    if (!limitedToken || !newPassword) {
      return { error: 'limitedToken and newPassword are required' };
    }
    let claims: any;
    try {
      claims = await verifyJwt(this.jwtService, limitedToken);
    } catch {
      throw new UnauthorizedException('Invalid or expired first-login token');
    }
    if (claims?.purpose !== 'first-login-password-change' || !claims?.email) {
      throw new UnauthorizedException('Token is not a first-login token');
    }
    const email = String(claims.email).toLowerCase().trim();
    const user = await this.userStorage.findOne(email);
    if (!user) throw new UnauthorizedException();
    if (!user.mustChangePassword) {
      Logger.warn(`completeFirstLogin called for ${email} but mustChangePassword is already false`);
    }
    const hashed = await hashPassword(newPassword);
    await this.userStorage.completeFirstLogin(email, hashed);

    await this.auditService.recordPasswordReset({
      targetUserId: user.userId,
      targetEmail: user.email,
      flow: 'first-login',
    });

    return await this.signIn(email, newPassword);
  }

  /**
   * Self-service password change for a logged-in user. Verifies the current
   * password before writing the new one. Returns 401 on a wrong current
   * password to keep timing-attack surface flat with sign-in.
   */
  async changePassword(email: string, currentPassword: string, newPassword: string) {
    if (!email || !currentPassword || !newPassword) {
      return { error: 'Email, currentPassword, and newPassword are required' };
    }
    const user = await this.userStorage.findOne(email);
    if (!user?.password) throw new UnauthorizedException();

    if (!(await verifyPassword(currentPassword, user.password))) throw new UnauthorizedException();

    const updated = { ...user, password: await hashPassword(newPassword) };
    await this.userStorage.update(email, updated);

    const targetUserId = user.userId ?? user.user_id;
    if (targetUserId) {
      await this.auditService.recordPasswordReset({
        targetUserId,
        targetEmail: email,
        flow: 'self-change',
      });
    }

    return { ...SUCCESS };
  }

  /**
   * Build the magic-link URL placed in the login email. Lands on the TMX
   * client's `#/magic/:code` route, which POSTs the code to /auth/magic/consume.
   */
  private buildMagicLinkUrl(code: string): string {
    const appConfig: any = this.configService.get('app');
    const base = String(appConfig?.baseUrl ?? process.env.APP_BASE_URL ?? '').replace(/\/+$/, '');
    if (!base) {
      throw new Error('APP_BASE_URL is not set; cannot generate magic-link.');
    }
    const tmxPath = `/${(process.env.TMX_URL ?? '/tmx/').replace(/^\/+|\/+$/g, '')}/`;
    return `${base}${tmxPath}#/magic/${code}`;
  }

  /**
   * Request a magic (passwordless) login link. Enumeration-defensive: always
   * returns `{ ok: true }`. A link is sent only when a user exists with this
   * verified contact_email AND has a password (SSO-only accounts must use their
   * org login). The code is single-use and expires in MAGIC_LINK_TTL_MINUTES.
   */
  async requestMagicLink(contactEmail: string): Promise<{ ok: true }> {
    const trimmed = (contactEmail ?? '').trim();
    if (!trimmed) return { ok: true };
    try {
      const user = await this.userStorage.findByContactEmail(trimmed);
      const eligible =
        user && user.emailVerifiedAt && user.userId && user.contactEmail && user.email && user.password;
      if (eligible) {
        const code = MAGIC_LINK_PREFIX + randomBytes(32).toString('base64url');
        const expiresAt = new Date(Date.now() + MAGIC_LINK_TTL_MS).toISOString();
        await this.authCodeStorage.setAccessCode(code, user.email, expiresAt);
        await this.emailService.sendTemplated({
          to: user.contactEmail,
          subject: 'Your CourtHive login link',
          template: 'magic-link',
          data: {
            firstName: user.firstName ?? '',
            magicLinkUrl: this.buildMagicLinkUrl(code),
            expiresInMinutes: MAGIC_LINK_TTL_MINUTES,
          },
          tag: 'magic-link',
        });
        Logger.log(`Sent magic-link to ${user.contactEmail} for user ${user.userId}`);
      } else {
        Logger.verbose(
          `requestMagicLink: no eligible recipient for "${trimmed}" (verified=${!!user?.emailVerifiedAt}, hasPassword=${!!user?.password})`,
        );
      }
    } catch (err) {
      Logger.warn(`requestMagicLink silently swallowed error: ${(err as Error).message}`);
    }
    return { ok: true };
  }

  /**
   * Consume a magic-link code and issue a full session (access + refresh). The
   * code is atomically deleted (single-use) and rejected if expired. SSO-only
   * accounts are blocked, consistent with the request gate.
   */
  async consumeMagicLink(code: string, userAgent?: string) {
    if (!code) throw new UnauthorizedException('Invalid or expired login link');
    const email = await this.authCodeStorage.consumeAccessCode(code);
    if (!email) throw new UnauthorizedException('Invalid or expired login link');

    const user = await this.userStorage.findOne(email);
    if (!user || !user.password) throw new UnauthorizedException();

    return this.startSession(user, userAgent);
  }

  /**
   * Create a user directly with an assigned password. SUPER_ADMIN unrestricted;
   * PROVIDER_ADMIN/PROVISIONER must pass a providerId scoped via
   * assertProviderEditor. When a deliverable contact_email is supplied, the new
   * user is emailed a 7-day set-your-password link instead of a clipboard
   * password. The created user is flagged mustChangePassword=true.
   */
  async adminCreateUser(
    body: {
      email: string;
      password?: string;
      contactEmail?: string;
      providerId?: string;
      providerRole?: string;
      firstName?: string;
      lastName?: string;
      phone?: string;
      roles?: string[];
      permissions?: string[];
      services?: string[];
    },
    editor?: { userContext?: UserContext; provisionerIds?: string[]; isProvisioner?: boolean },
  ) {
    const email = (body?.email ?? '').toLowerCase().trim();
    if (!email) return { error: 'Email is required' };

    const requestedRoles: string[] = body?.roles ?? [];
    const invalidRoles = requestedRoles.filter((r) => !ALLOWED_ROLE_SET.has(r));
    if (invalidRoles.length) {
      return { error: `Invalid role(s): ${invalidRoles.join(', ')}` };
    }

    const providerRole: string = body?.providerRole === 'PROVIDER_ADMIN' ? 'PROVIDER_ADMIN' : 'DIRECTOR';

    const providerId = body?.providerId?.trim() || undefined;
    const editorContext = editor?.userContext;
    if (!editorContext?.isSuperAdmin) {
      if (!providerId) {
        throw new BadRequestException('providerId is required when the editor is not SUPER_ADMIN');
      }
      await assertProviderEditor({
        userContext: editorContext,
        providerId,
        provisionerIds: editor?.provisionerIds,
        provisionerProviderStorage: this.provisionerProviderStorage,
        isProvisioner: editor?.isProvisioner,
      });
      // A new account holds nothing yet, so every restricted role it is created with is a grant.
      // Without this, a provider admin could mint a super-admin through the create path.
      assertNoPrivilegeEscalation(requestedRoles, []);
    }

    const existing = await this.userStorage.findOne(email);
    if (existing?.email) {
      throw new ConflictException(
        'A user with that email already exists. Use the existing-user association flow to add them to a provider.',
      );
    }

    const contactEmailRaw = (body?.contactEmail ?? '').trim();
    const willEmail = !!contactEmailRaw && EMAIL_REGEX.test(contactEmailRaw);

    const supplied = (body?.password ?? '').trim();
    const password = supplied || createUniqueKey().slice(0, 12);

    const result: any = await this.userStorage.create({
      firstName: body.firstName,
      lastName: body.lastName,
      phone: body.phone,
      roles: body.roles ?? [],
      permissions: body.permissions ?? [],
      services: body.services,
      email,
      password: await hashPassword(password),
      mustChangePassword: true,
    } as any);
    if (result?.error) return result;

    const created = await this.userStorage.findOne(email);
    const userId = created?.userId ?? created?.user_id;

    if (providerId && userId) {
      try {
        await this.userProviderStorage.upsert({ userId, providerId, providerRole });
      } catch (err) {
        Logger.warn(`Failed to upsert user_providers row for ${email}: ${(err as Error).message}`);
      }
    }

    if (willEmail && userId) {
      try {
        await this.userStorage.setContactEmail(userId, contactEmailRaw);
        await this.issueAndSendResetEmail(
          { userId, contactEmail: contactEmailRaw, firstName: body.firstName },
          {
            expiresIn: ADMIN_ONBOARD_TOKEN_TTL,
            template: 'admin-created-account',
            subject: 'Welcome to CourtHive — set your password',
            tag: 'admin-onboard',
          },
        );
        Logger.log(`Sent admin-onboard mail to ${contactEmailRaw} for user ${userId}`);
        return {
          success: true,
          email,
          providerId,
          providerRole,
          mode: 'email-sent' as const,
          contactEmail: contactEmailRaw,
        };
      } catch (err) {
        Logger.warn(`adminCreateUser email-onboard fell back to clipboard for ${email}: ${(err as Error).message}`);
      }
    }

    return {
      success: true,
      email,
      password,
      providerId,
      providerRole,
      mode: 'password-returned' as const,
    };
  }

  /**
   * Reset a user's password as an administrator. SUPER_ADMIN unrestricted;
   * otherwise the editor must have edit authority at one of the target's
   * provider associations.
   */
  async adminResetPassword(
    rawEmail: string,
    newPassword?: string,
    editor?: { userContext?: UserContext; provisionerIds?: string[]; isProvisioner?: boolean },
  ) {
    if (!rawEmail) return { error: 'Email is required' };
    const email = rawEmail.toLowerCase().trim();
    const user = await this.userStorage.findOne(email);
    if (!user) return { error: 'User not found' };

    const editorContext = editor?.userContext;
    if (!editorContext?.isSuperAdmin) {
      const targetUserId = user.userId ?? user.user_id;
      const targetRows = targetUserId ? await this.userProviderStorage.findByUserId(targetUserId) : [];
      let allowed = false;
      for (const row of targetRows) {
        try {
          await assertProviderEditor({
            userContext: editorContext,
            providerId: row.providerId,
            provisionerIds: editor?.provisionerIds,
            provisionerProviderStorage: this.provisionerProviderStorage,
            isProvisioner: editor?.isProvisioner,
          });
          allowed = true;
          break;
        } catch {
          // Try the next provider association.
        }
      }
      if (!allowed) {
        throw new ForbiddenException('Not authorised to reset this user’s password');
      }
    }

    const password = newPassword || createUniqueKey().slice(0, 12);
    user.password = await hashPassword(password);
    await this.userStorage.update(email, user);

    const targetUserId = user.userId ?? user.user_id;
    if (targetUserId) {
      await this.auditService.recordPasswordReset({
        targetUserId,
        targetEmail: email,
        flow: 'admin-reset',
        actorUserId: editor?.userContext?.userId,
        actorEmail: editor?.userContext?.email,
      });

      this.refreshTokenService.revokeAllForUser(targetUserId).catch((err: any) => {
        Logger.warn(`revokeAllForUser(${targetUserId}) after admin reset failed: ${err?.message ?? err}`, AuthService.name);
      });
    }
    return { ...SUCCESS, password };
  }

  async modifyUser(
    params: { email: string; [key: string]: any },
    editor?: { userContext?: UserContext; provisionerIds?: string[]; isProvisioner?: boolean },
  ) {
    // Credentials are not profile fields: a password changes only through the reset and change-password flows,
    // which hash it and audit the change. Taken out here so this route can never write one.
    const { email: rawEmail, contactEmail, password: _password, mustChangePassword: _mustChange, ...updates } = params;
    if (!rawEmail) return { error: 'Email is required' };
    const email = rawEmail.toLowerCase().trim();

    const user = await this.userStorage.findOne(email);
    if (!user) return { error: 'User not found' };

    const editorContext = editor?.userContext;
    if (!editorContext?.isSuperAdmin) {
      await this.assertModifyUserAuthority(user, editor);
      assertNoPrivilegeEscalation(updates.roles, user.roles);
    }

    const contactEmailChange = this.resolveContactEmailChange(user, contactEmail);
    if (contactEmailChange === 'invalid') {
      return { error: 'contactEmail is not a valid email address' };
    }

    const merged = { ...user, ...updates };
    await this.userStorage.update(email, merged);

    let responseContactEmail = user.contactEmail ?? user.contact_email;
    let responseEmailVerifiedAt = user.emailVerifiedAt ?? user.email_verified_at ?? null;
    if (contactEmailChange !== null) {
      const userId = user.userId ?? user.user_id;
      if (userId) {
        await this.userStorage.setContactEmail(userId, contactEmailChange);
        responseContactEmail = contactEmailChange;
        responseEmailVerifiedAt = null;

        await this.auditService.recordContactEmailChanged({
          targetUserId: userId,
          targetEmail: email,
          actorUserId: editor?.userContext?.userId,
          actorEmail: editor?.userContext?.email,
          oldContactEmail: user.contactEmail ?? user.contact_email ?? null,
          newContactEmail: contactEmailChange,
          source: 'admin',
        });

        if (contactEmailChange) {
          try {
            await this.identityService.resendVerification({ userId, email, firstName: user.firstName });
          } catch (err) {
            Logger.warn(
              `modifyUser: verification mail to ${contactEmailChange} for ${email} failed: ${(err as Error).message}`,
              AuthService.name,
            );
          }
        }
      }
    }

    const { password: _, ...safeUser } = merged;  
    return {
      success: true,
      user: { ...safeUser, contactEmail: responseContactEmail, emailVerifiedAt: responseEmailVerifiedAt },
    };
  }

  /** Throws ForbiddenException if the editor has authority over none of the target's provider associations. */
  private async assertModifyUserAuthority(
    user: any,
    editor?: { userContext?: UserContext; provisionerIds?: string[]; isProvisioner?: boolean },
  ): Promise<void> {
    const targetUserId = user.userId ?? user.user_id;
    const targetRows = targetUserId ? await this.userProviderStorage.findByUserId(targetUserId) : [];
    for (const row of targetRows) {
      try {
        await assertProviderEditor({
          userContext: editor?.userContext,
          providerId: row.providerId,
          provisionerIds: editor?.provisionerIds,
          provisionerProviderStorage: this.provisionerProviderStorage,
          isProvisioner: editor?.isProvisioner,
        });
        return;
      } catch {
        // Try the next provider association.
      }
    }
    throw new ForbiddenException('Not authorised to modify this user');
  }

  /**
   * Returns the normalized new contact_email if changed, `null` if omitted or
   * unchanged (case-insensitive), or `'invalid'` if non-empty but not
   * RFC-shaped. Empty string means "clear contact_email".
   */
  private resolveContactEmailChange(user: any, incoming: string | undefined): string | null | 'invalid' {
    if (incoming === undefined) return null;
    const trimmed = (incoming ?? '').trim();
    const current = (user.contactEmail ?? user.contact_email ?? '').trim();
    if (trimmed.toLowerCase() === current.toLowerCase()) return null;
    if (trimmed && !EMAIL_REGEX.test(trimmed)) return 'invalid';
    return trimmed;
  }

  async removeUser(params: any) {
    return await this.userStorage.remove(params.email);
  }

  async getUsers() {
    return await this.userStorage.findAll();
  }

  async decode(token: string) {
    try {
      return await verifyJwt(this.jwtService, token);
    } catch {
      throw new UnauthorizedException('Incorrect auth token.');
    }
  }
}
