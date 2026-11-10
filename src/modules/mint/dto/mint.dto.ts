// Request body for POST /internal/mint (the internal SPLIT-token signer).
//
// CFS authorizes the mint locally (tournament ownership / provisioner state) and
// sends the ALREADY-AUTHORIZED claims here for signing. The IdP does not
// re-authorize — it trusts the service-token-guarded caller — but it hard-pins
// the audience allow-list, a max TTL, and strips any caller-supplied header /
// timing / issuer claims (see mint.service.ts). `expiresIn` is seconds.

export interface MintRequestDto {
  /** The claims to sign (e.g. sub, tournamentId, personId). `aud` here is ignored — see `audience`. */
  claims: Record<string, unknown>;
  /** Requested token audience — must be one of the mint allow-list (score / provider / admin). */
  audience: string;
  /** Token lifetime in seconds. Clamped to the mint max TTL. */
  expiresIn: number;
}
