/**
 * MintService — the IdP-internal signer for CFS's SPLIT tournament tokens.
 *
 * CFS keeps the SPLIT controllers + tournament/provisioner AUTHORIZATION (it owns
 * the data + `canMutateTournament`) but holds NO signing key. It calls this
 * endpoint — service-token guarded — to sign already-authorized claims. This is
 * the ONLY way CFS gets a signed tournament token after the key is removed from it.
 *
 * The IdP TRUSTS the authorization (the service token is the trust boundary) but
 * hard-pins, defense-in-depth ("trust + hard-pin"):
 *   1. `audience` must be one of the mint allow-list (score / provider / admin) —
 *      a compromised caller can't mint an `admin`-session-shaped token for an
 *      arbitrary aud, and can never widen beyond these three.
 *   2. `expiresIn` is clamped to MINT_MAX_TTL_SECONDS — a bounded lifetime even if
 *      the caller's own per-audience clamp regresses.
 *   3. Header / timing / issuer claims (`alg`, `kid`, `exp`, `iat`, `nbf`, `iss`,
 *      `aud`) are STRIPPED from the incoming claims — the caller can never
 *      override the signing algorithm, key id, issuer, or audience. `aud` is set
 *      from the validated `audience` param alone.
 *
 * Fail-closed (architectural-standards A3): if ES256 signing is not actually
 * enabled on this IdP (no private key / flag off), the mint REFUSES rather than
 * falling back to HS256 — an HS256 token would be rejected by every ES256-only
 * verifier, so emitting one is worse than an explicit 503.
 */
import { BadRequestException, Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { isEs256SigningEnabled, signJwt } from 'src/common/auth/signJwt';
import { MintRequestDto } from './dto/mint.dto';

/** Audiences the mint endpoint will sign. Never widen without a security review. */
export const MINT_ALLOWED_AUDIENCES = new Set(['score', 'provider', 'admin']);

/** Absolute ceiling on a minted token's lifetime — the widest SPLIT token is the
 * provider tracker token (8h). Per-audience clamps stay CFS-side (authorization). */
export const MINT_MAX_TTL_SECONDS = 28800; // 8 hours
const MINT_MIN_TTL_SECONDS = 1;

/** Claims the caller may never set — the signer owns these. */
const RESERVED_CLAIMS = new Set(['alg', 'kid', 'exp', 'iat', 'nbf', 'iss', 'aud']);

@Injectable()
export class MintService {
  private readonly logger = new Logger(MintService.name);

  constructor(private readonly jwtService: JwtService) {}

  async mint(body: MintRequestDto): Promise<{ token: string }> {
    const audience = typeof body?.audience === 'string' ? body.audience.trim() : '';
    if (!MINT_ALLOWED_AUDIENCES.has(audience)) {
      throw new BadRequestException(`audience must be one of: ${[...MINT_ALLOWED_AUDIENCES].join(', ')}`);
    }

    const expiresIn = this.clampTtl(body?.expiresIn);

    const claims = body?.claims;
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
      throw new BadRequestException('claims must be an object');
    }

    // Fail-closed: never emit an HS256 token a verifier would reject.
    if (!isEs256SigningEnabled()) {
      this.logger.error('mint refused — ES256 signing is not enabled on this IdP (missing key or JWT_SIGN_ES256)');
      throw new ServiceUnavailableException('signer not configured');
    }

    const payload = { ...stripReservedClaims(claims), aud: audience };
    const token = await signJwt(this.jwtService, payload, { expiresIn });

    this.logger.verbose(`minted ${audience} token (ttl=${expiresIn}s)`);
    return { token };
  }

  private clampTtl(raw: unknown): number {
    if (typeof raw !== 'number' || !Number.isFinite(raw)) {
      throw new BadRequestException('expiresIn must be a finite number of seconds');
    }
    if (raw < MINT_MIN_TTL_SECONDS) {
      throw new BadRequestException(`expiresIn below the floor of ${MINT_MIN_TTL_SECONDS}s`);
    }
    if (raw > MINT_MAX_TTL_SECONDS) {
      throw new BadRequestException(`expiresIn above the ceiling of ${MINT_MAX_TTL_SECONDS}s`);
    }
    return Math.floor(raw);
  }
}

/** Return a shallow copy of `claims` with every reserved (signer-owned) key removed. */
function stripReservedClaims(claims: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(claims).filter(([key]) => !RESERVED_CLAIMS.has(key)));
}
