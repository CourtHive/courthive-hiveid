# courthive-hiveid

The **HiveID identity provider (IdP)** for the [CourtHive](https://courthive.com) competition
management platform. It owns login, sessions and accounts, and it is the **only service that signs
tokens**. [competition-factory-server](https://github.com/CourtHive/competition-factory-server) (CFS)
and the other CourtHive services are relying parties: they verify tokens with the IdP's public key
and never sign their own.

[TMX](https://github.com/CourtHive/TMX), the tournament management client, calls the IdP for
everything under `/auth/*` and `/account/*`, apart from the routes listed under
[Routing](#routing) below.

## What it does

- **Admin sessions:** password login, refresh, logout, a two-step login for users with more than one
  provider, first-login password change, change/forgot/reset password, and magic-link login.
- **User administration** for superadmins: create, modify, reset and remove users.
- **HiveID accounts:** self-signup and contact-email verification for players and other individuals.
- **Token signing:** ES256 tokens with a `kid` header, and a JWKS document at
  `GET /.well-known/jwks.json`. CFS asks the IdP to sign tournament-scoped tokens (tracker, scorer,
  provider scoring) through an internal endpoint, `POST /internal/mint`, guarded by a shared service
  token. CFS decides who may have those tokens; the IdP only signs them.

## Architecture

- **NestJS 11**, Node ≥ 24, pnpm. Vanilla `pg` with parameterized queries, no ORM.
- **One database shared with CFS.** The `users`, `user_providers` and `providers` tables live in
  CFS's PostgreSQL database, and **CFS's migrations create them**. The IdP opens its own connection
  and owns writes to `users`; CFS keeps a read for role hydration.
- **No global prefix.** Routes mount at the root (`/auth`, `/account`, …) so a reverse proxy can
  route by path without the clients changing.
- **Fail closed.** The internal signer rejects every request when `HIVEID_SIGNER_TOKEN` is unset, and
  the service refuses to boot in production without it. `GET /health/core-db` returns 503 when the
  database is unreachable.

## Self-hosting

You need a running CFS (which provides the database schema), this service, and a reverse proxy in
front of both.

1. **Start CFS once** so its migrations create the schema.
2. **Generate an ES256 key pair** (P-256):

   ```bash
   openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out jwt-private.pem
   openssl ec -in jwt-private.pem -pubout -out jwt-public.pem
   ```

3. **Configure the IdP:** copy [`.env.example`](.env.example) to `.env`. Set the `PG_*` values
   (CFS's database), `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `JWT_KID` (any stable name, e.g.
   `es256-2026-01`), `JWT_SIGN_ES256=true`, and a random `HIVEID_SIGNER_TOKEN`.
4. **Configure CFS** to trust the IdP:
   - `JWT_PUBLIC_KEY` and `JWT_KID`: the same public key and kid. **Never** give CFS the private key.
   - `HIVEID_BASE_URL`: where CFS can reach the IdP, e.g. `http://localhost:3140`.
   - `HIVEID_SIGNER_TOKEN`: the same value as the IdP's.
5. **Create the first administrator** with CFS's script, which stores a bcrypt hash:

   ```bash
   node src/scripts/admin-user.mjs create --email admin@example.com --password '<password>'
   ```

6. **Build and start the IdP:** `pnpm install && pnpm build && pnpm start`.

Email (`RESEND_API_KEY`, `EMAIL_FROM`) and courthive-persons (`PERSONS_BASE_URL`) are optional.
Without email, password login works and the flows that send mail fail with a clear error. Persons
is used only by HiveID self-signup.

### Routing

Send `/auth/*` and `/account/*` to the IdP, **except** these routes, which stay on CFS because they
need tournament data:

| Path                                                                        | Why it stays on CFS                                                                          |
| --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `/auth/tracker-token`, `/auth/scorer-token`, `/auth/provider-scoring-token` | CFS authorizes tournament-scoped tokens, then calls the IdP's `/internal/mint` to sign them. |
| `/auth/sso/*`                                                               | Provisioner single sign-on.                                                                  |
| `/auth/hiveid/me/claimable/*`, `/auth/hiveid/me/claim`                      | Claiming tournament participations.                                                          |

**Never expose `/internal/mint` publicly.** Only CFS should reach it, directly over the private
network.

An nginx sketch (exact and prefix matches win over the regex):

```nginx
location = /auth/tracker-token          { proxy_pass http://cfs:8383; }
location = /auth/scorer-token           { proxy_pass http://cfs:8383; }
location = /auth/provider-scoring-token { proxy_pass http://cfs:8383; }
location ^~ /auth/sso/                  { proxy_pass http://cfs:8383; }
location ^~ /auth/hiveid/me/claimable/  { proxy_pass http://cfs:8383; }
location = /auth/hiveid/me/claim        { proxy_pass http://cfs:8383; }
location = /internal/mint               { return 404; }
location ~ ^/(auth|account)/            { proxy_pass http://hiveid:3140; }
```

### Upgrading from an older CFS

Older CFS releases could store a password as plaintext. The IdP accepts only bcrypt hashes, so run
`node scripts/hash-plaintext-passwords.mjs` (a dry run) and then with `--apply` before the first
login. It hashes each plaintext value in place, so the existing passwords keep working.

## Commands

```bash
pnpm install
pnpm build          # nest build -> build/
pnpm start          # production
pnpm watch          # dev (watch)
pnpm check-types    # tsc --noEmit
pnpm lint           # ESLint — non-mutating, fails on any warning
pnpm lint:fix       # ESLint with auto-fix (rewrites source)
pnpm test           # vitest
```

## Health

- `GET /health`: liveness.
- `GET /health/core-db`: checks the connection to the shared database (503 when it fails).

## License

MIT — see [LICENSE](LICENSE).
