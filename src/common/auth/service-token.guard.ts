// ServiceTokenGuard — guards the internal /internal/mint endpoint that CFS calls
// to sign already-authorized SPLIT tournament tokens. CFS presents a shared secret in `x-service-token`; we compare it to
// HIVEID_SIGNER_TOKEN with a constant-time check.
//
// Fail closed: if the server has no configured
// token, every request is rejected rather than admitted — an unset secret must
// never open the signer. Boot-time validation additionally refuses to start in
// production without the token (config/env.ts).
//
// Mirrors courthive-declarations/src/common/auth/service-token.guard.ts.

import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { timingSafeEqual } from 'crypto';

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

@Injectable()
export class ServiceTokenGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const configured = process.env.HIVEID_SIGNER_TOKEN ?? '';
    if (!configured) throw new UnauthorizedException();

    const request = context.switchToHttp().getRequest();
    const presented = request.headers?.['x-service-token'];
    if (typeof presented !== 'string' || !safeEqual(presented, configured)) {
      throw new UnauthorizedException();
    }
    return true;
  }
}
