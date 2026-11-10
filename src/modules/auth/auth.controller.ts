import { Body, Controller, Get, HttpCode, HttpStatus, Patch, Post, Req } from '@nestjs/common';

import { UserCtx, type UserContext } from 'src/common/auth/decorators/user-context.decorator';
import { CLIENT, SUPER_ADMIN } from 'src/common/constants/roles';
import { Audience } from 'src/common/auth/decorators/audience.decorator';
import { Public } from 'src/common/auth/decorators/public.decorator';
import { Roles } from 'src/common/auth/decorators/roles.decorator';
import { User } from 'src/common/auth/decorators/user.decorator';
import { AdminCreateUserDto } from './dto/adminCreateUser.dto';
import { ForgotPasswordDto } from './dto/forgotPassword.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { ModifyUserDto } from './dto/modifyUser.dto';
import { RemoveDto } from './dto/remove.dto';
import { SignInDto } from './dto/signIn.dto';
import { AuthService } from './auth.service';

// Session/login surface of the HiveID IdP (ported from CFS account/auth).
// This slice: password login, refresh, logout, me, last-selected-provider.
// The admin / magic-link / password-reset routes land with the email + audit
// increments. Per-IP throttling (@nestjs/throttler in CFS) is a follow-up.
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  signIn(@Body() signIn: SignInDto, @Req() req?: any) {
    return this.authService.signIn(signIn.email, signIn.password, req?.headers?.['user-agent']);
  }

  /**
   * Exchange a rotating refresh token for a fresh access token (+ rotated
   * refresh token). Public: the refresh token is the credential.
   */
  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(@Body() body: { refreshToken: string }, @Req() req?: any) {
    return this.authService.refreshSession(body?.refreshToken ?? '', req?.headers?.['user-agent']);
  }

  /** Revoke a refresh token (logout). Idempotent. Public: the token is the credential. */
  @Public()
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Body() body: { refreshToken: string }) {
    return this.authService.logout(body?.refreshToken ?? '');
  }

  /**
   * The session for a chosen provider: after login with the selection token, or to SWITCH with a full
   * session token. No @Roles: the selection token carries none by design (see AuthService.selectProvider).
   */
  @Post('select-provider')
  @Audience(['provider-selection', 'admin'])
  @HttpCode(HttpStatus.OK)
  selectProvider(@Body() body: { providerId: string }, @User() caller: any, @Req() req?: any) {
    return this.authService.selectProvider(body?.providerId, caller, req?.headers?.['user-agent']);
  }

  @Get('me')
  @Roles([CLIENT, SUPER_ADMIN])
  @HttpCode(HttpStatus.OK)
  getMe(@UserCtx() ctx: UserContext) {
    return ctx;
  }

  @Patch('me/last-selected-provider')
  @Roles([CLIENT, SUPER_ADMIN])
  @HttpCode(HttpStatus.OK)
  updateLastSelectedProvider(@Body() body: { providerId: string | null }, @UserCtx() userContext?: UserContext) {
    if (!userContext?.email) return { error: 'Authentication required' };
    return this.authService.updateLastSelectedProvider(userContext.email, body?.providerId ?? null, {
      isSuperAdmin: !!userContext.isSuperAdmin,
    });
  }

  /** Complete the forced first-login password change. Public: the limited token is the credential. */
  @Public()
  @Post('complete-first-login')
  @HttpCode(HttpStatus.OK)
  completeFirstLogin(@Body() body: { limitedToken: string; newPassword: string }) {
    return this.authService.completeFirstLogin(body?.limitedToken, body?.newPassword);
  }

  @Post('change-password')
  @Roles([CLIENT, SUPER_ADMIN])
  @HttpCode(HttpStatus.OK)
  changePassword(@Body() body: { currentPassword: string; newPassword: string }, @UserCtx() userContext?: UserContext) {
    if (!userContext?.email) return { error: 'Authentication required' };
    return this.authService.changePassword(userContext.email, body.currentPassword, body.newPassword);
  }

  /**
   * Request a password reset. Always returns `{ ok: true }` (enumeration
   * defense) — mail is sent only to a registered, verified contact. Public.
   */
  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  forgotPassword(@Body() body: ForgotPasswordDto) {
    return this.authService.forgotPassword(body?.contactEmail ?? '');
  }

  /** Apply a password reset using the JWT from the reset email. Public: the token is the auth. */
  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  resetPassword(@Body() body: ResetPasswordDto) {
    return this.authService.resetPassword(body?.token ?? '', body?.newPassword ?? '');
  }

  /**
   * Request a passwordless magic login link. Enumeration-defensive: always
   * returns `{ ok: true }`; a link is sent only to a verified, non-SSO account.
   */
  @Public()
  @Post('magic/request')
  @HttpCode(HttpStatus.OK)
  requestMagicLink(@Body() body: { email: string }) {
    return this.authService.requestMagicLink(body?.email ?? '');
  }

  /** Consume a magic-link code and issue a session. Public: the single-use code is the credential. */
  @Public()
  @Post('magic/consume')
  @HttpCode(HttpStatus.OK)
  consumeMagicLink(@Body() body: { code: string }, @Req() req?: any) {
    return this.authService.consumeMagicLink(body?.code ?? '', req?.headers?.['user-agent']);
  }

  // --- Admin user management (CLIENT gate; service narrows to SUPER_ADMIN or a
  // provider-scoped editor via assertProviderEditor). ---

  @Post('admin-create-user')
  @Roles([CLIENT, SUPER_ADMIN])
  @HttpCode(HttpStatus.OK)
  adminCreateUser(@Body() body: AdminCreateUserDto, @User() user?: any, @UserCtx() userContext?: UserContext, @Req() req?: any) {
    return this.authService.adminCreateUser(body, {
      userContext,
      provisionerIds: user?.provisionerIds,
      isProvisioner: !!req?.provisioner,
    });
  }

  @Post('modify')
  @Roles([CLIENT, SUPER_ADMIN])
  @HttpCode(HttpStatus.OK)
  modify(@Body() params: ModifyUserDto, @User() user?: any, @UserCtx() userContext?: UserContext, @Req() req?: any) {
    return this.authService.modifyUser(params, {
      userContext,
      provisionerIds: user?.provisionerIds,
      isProvisioner: !!req?.provisioner,
    });
  }

  @Post('admin-reset-password')
  @Roles([CLIENT, SUPER_ADMIN])
  @HttpCode(HttpStatus.OK)
  adminResetPassword(@Body() body: { email: string; newPassword?: string }, @User() user?: any, @UserCtx() userContext?: UserContext, @Req() req?: any) {
    return this.authService.adminResetPassword(body.email, body.newPassword, {
      userContext,
      provisionerIds: user?.provisionerIds,
      isProvisioner: !!req?.provisioner,
    });
  }

  @Post('remove')
  @Roles([SUPER_ADMIN])
  @HttpCode(HttpStatus.OK)
  remove(@Body() params: RemoveDto) {
    return this.authService.removeUser(params);
  }

  @Post('allusers')
  @Roles([SUPER_ADMIN])
  @HttpCode(HttpStatus.OK)
  allUsers() {
    return this.authService.getUsers();
  }
}
