import { Injectable } from '@nestjs/common';

// Minimal HTTP client to courthive-persons — the resolve/mint + getById surface
// the HiveID signup flow needs. (Mint happens server-side in persons; `resolve`
// returns status:'minted' for a newly-created canonical person.)
//
// NOT ported here: the CFS PersonsClient's always-on SSE consumer that rewrites
// cached person fields onto `users` on personMerged events + fans out via a WS
// gateway. That background sync stays on CFS while auth is dual-run; it moves to
// the IdP as a follow-up.

const DEFAULT_PERSONS_BASE_URL = 'http://localhost:3100';

/**
 * Shared secret presented to courthive-persons as `X-Service-Token`. persons
 * requires it on every route except /health. Read at
 * call time, matching how `baseUrl` is read below, so the secret can be
 * rotated without a restart.
 *
 * Omitted when unset — additive against a persons that does not yet enforce
 * it, which is what lets consumers ship before the service starts rejecting.
 */
function serviceTokenHeaders(): Record<string, string> {
  const token = process.env.PERSONS_SERVICE_TOKEN;
  return token ? { 'X-Service-Token': token } : {};
}

export interface PersonOtherId {
  provider: string;
  externalId: string;
}

export interface PersonFragmentInput {
  standardFamilyName?: string;
  standardGivenName?: string;
  birthDate?: string;
  sex?: string;
  nationalityCode?: string;
  tennisId?: string;
  personOtherIds?: PersonOtherId[];
  source?: string;
}

export interface ResolveResult {
  status: 'resolved' | 'minted' | 'candidate' | 'incomplete';
  personId?: string;
  personRevision?: number;
  candidates?: { personId: string; confidence: number }[];
  missingFields?: string[];
}

export interface PersonRow {
  personId: string;
  standardFamilyName: string | null;
  standardGivenName: string | null;
  birthDate: string | null;
  sex: string | null;
  nationalityCode: string | null;
  tennisId: string | null;
  mergedInto: string | null;
  personRevision: number;
}

export interface PersonWithAliases {
  person: PersonRow;
  aliases: { provider: string; externalId: string }[];
}

@Injectable()
export class PersonsClient {
  // Read at call time so PERSONS_BASE_URL can be provisioned without a restart
  // and tests can point it at a mock.
  private get baseUrl(): string {
    return (process.env.PERSONS_BASE_URL ?? DEFAULT_PERSONS_BASE_URL).replace(/\/+$/, '');
  }

  async resolve(fragment: PersonFragmentInput): Promise<ResolveResult> {
    const res = await fetch(`${this.baseUrl}/persons/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...serviceTokenHeaders() },
      body: JSON.stringify(fragment),
    });
    if (!res.ok) {
      throw new Error(`persons resolve failed: HTTP ${res.status}`);
    }
    return (await res.json()) as ResolveResult;
  }

  async getById(personId: string): Promise<PersonWithAliases | null> {
    const res = await fetch(`${this.baseUrl}/persons/${encodeURIComponent(personId)}`, {
      headers: serviceTokenHeaders(),
    });
    if (res.status === 404) return null;
    if (!res.ok) {
      throw new Error(`persons getById failed: HTTP ${res.status}`);
    }
    return (await res.json()) as PersonWithAliases;
  }
}
