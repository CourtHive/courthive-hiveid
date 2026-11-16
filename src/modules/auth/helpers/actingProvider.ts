/**
 * THE PROVIDER A SESSION ACTS FOR.
 *
 * A user associated with more than one provider is never placed in one automatically; they
 * choose at login, and the session's `providerId` claim is that choice. To work for another provider they
 * switch, which issues a new session.
 */

export const PROVIDER_SELECTION_PURPOSE = 'provider-selection';
/** Not `admin`: every admin route, in every service that checks `aud`, refuses a selection token. */
export const PROVIDER_SELECTION_AUDIENCE = 'provider-selection';
export const PROVIDER_SELECTION_TTL = '10m';

export function resolveActingProviderId({
  provisionerProviderIds,
  associatedIds,
  isSuperAdmin,
  requested,
}: {
  /** Providers the user's provisioners manage: a provisioner may act for these too. */
  provisionerProviderIds: string[];
  associatedIds: string[];
  isSuperAdmin: boolean;
  /** An explicit choice: select-provider, or a refreshed session that made one. */
  requested?: string;
}): string | undefined {
  if (requested) {
    const allowed = isSuperAdmin || associatedIds.includes(requested) || provisionerProviderIds.includes(requested);
    return allowed ? requested : undefined;
  }
  // One association is the session's provider. None, or several with no choice made, acts for NONE: the
  // legacy users.provider_id "home" is no longer read, so there is nothing to default to.
  return associatedIds.length === 1 ? associatedIds[0] : undefined;
}

export type ChoosableProvider = {
  organisationAbbreviation?: string;
  organisationName?: string;
  providerRole?: string;
  providerId: string;
  /** Reached through one of the user's provisioners, not a direct association. */
  viaProvisioner?: true;
};

/**
 * THE PICKER'S LIST: the user's own providers, then those their provisioners manage that they are not directly
 * associated with — every provider `resolveActingProviderId` would accept. Only the list grows: WHEN the picker
 * appears is still decided by the direct associations alone, so a login that gets its session at once (a
 * headless client with one association) still does.
 */
export function choosableProviders(
  associations: ChoosableProvider[],
  provisionerProviders: Array<{ providerId: string; organisationName?: string; organisationAbbreviation?: string }> = [],
): ChoosableProvider[] {
  const seen = new Set(associations.map((a) => a.providerId));
  const inherited = provisionerProviders
    .filter((p) => !seen.has(p.providerId))
    .map((p) => ({
      providerId: p.providerId,
      organisationName: p.organisationName,
      organisationAbbreviation: p.organisationAbbreviation,
      viaProvisioner: true as const,
    }));
  return [...associations, ...inherited];
}
