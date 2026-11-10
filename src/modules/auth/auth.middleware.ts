import { Inject, Injectable, NestMiddleware } from '@nestjs/common';

import {
  USER_PROVIDER_STORAGE,
  USER_PROVISIONER_STORAGE,
  PROVISIONER_PROVIDER_STORAGE,
  USER_STORAGE,
  type IUserProviderStorage,
  type IUserProvisionerStorage,
  type IProvisionerProviderStorage,
  type IUserStorage,
} from 'src/storage/interfaces';
import { buildUserContext } from 'src/common/auth/helpers/buildUserContext';
import { AuthService } from './auth.service';

/**
 * Returns true when the token's `aud` claim grants admin access — either the
 * claim is missing (legacy tokens), is the string 'admin', or is an array
 * containing 'admin'.
 */
function tokenHasAdminAudience(aud: unknown): boolean {
  if (aud == null) return true;
  if (typeof aud === 'string') return aud === 'admin';
  if (Array.isArray(aud)) return aud.includes('admin');
  return false;
}

/**
 * Ported from competition-factory-server's account/auth.middleware. Hydrates
 * `req.user` + `req.userContext` from a bearer token so `@UserCtx` works on the
 * authed routes. Reads `users` directly via USER_STORAGE (the CFS dev-mode
 * UsersService is intentionally not ported).
 */
@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(
    private readonly authService: AuthService,
    @Inject(USER_STORAGE) private readonly userStorage: IUserStorage,
    @Inject(USER_PROVIDER_STORAGE) private readonly userProviderStorage: IUserProviderStorage,
    @Inject(USER_PROVISIONER_STORAGE) private readonly userProvisionerStorage: IUserProvisionerStorage,
    @Inject(PROVISIONER_PROVIDER_STORAGE)
    private readonly provisionerProviderStorage: IProvisionerProviderStorage,
  ) {}

  async use(req: any, _res: any, next: () => void): Promise<void> {
    let jwtPayload: any;

    if (req.baseUrl === '') {
      next();
      return;
    }
    if (req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts[1]) {
        try {
          jwtPayload = await this.authService.decode(parts[1]);
        } catch {
          // Invalid/expired token — AuthGuard handles the 401. Expected for
          // stale client tokens; no need to log here.
        }
      }
    }

    // Limited-purpose tokens (e.g. first-login-password-change) carry a
    // `purpose` claim and must not authenticate normal endpoints.
    if (jwtPayload?.email != null && !jwtPayload?.purpose) {
      const user = await this.userStorage.findOne(jwtPayload.email);
      req.user = user;

      // Hydrate the multi-provider UserContext only for admin-audience tokens.
      if (user && tokenHasAdminAudience(jwtPayload.aud)) {
        req.userContext = await buildUserContext(user, {
          userProviderStorage: this.userProviderStorage,
          userProvisionerStorage: this.userProvisionerStorage,
          provisionerProviderStorage: this.provisionerProviderStorage,
        });
      }
    }

    next();
  }
}
