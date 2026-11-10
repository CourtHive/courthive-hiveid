import { Controller, Get, Header } from '@nestjs/common';

import { Public } from 'src/common/auth/decorators/public.decorator';
import { getJwks } from '../../common/auth/jwtKeys';

// Publishes the IdP's ES256 PUBLIC key(s) so relying parties can verify by kid.
// While the keypair is shared with CFS (same kid), CFS also serves an identical
// JWKS; once the IdP is the sole signer this becomes the canonical source.
// Public, cacheable, never carries private material.
@Public()
@Controller('.well-known')
export class JwksController {
  @Get('jwks.json')
  @Header('Cache-Control', 'public, max-age=300')
  jwks() {
    return getJwks();
  }
}
