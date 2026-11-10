import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';

import { ServiceTokenGuard } from 'src/common/auth/service-token.guard';
import { Public } from 'src/common/auth/decorators/public.decorator';
import { MintRequestDto } from './dto/mint.dto';
import { MintService } from './mint.service';

/**
 * Internal signer for CFS's SPLIT tournament tokens.
 *
 * NOT a user-facing route: `@Public()` bypasses the JWT AuthGuard, and
 * `ServiceTokenGuard` gates it on the shared `HIVEID_SIGNER_TOKEN` (x-service-token
 * header). A reverse proxy should never expose this path publicly; the
 * endpoint lives here because only the IdP holds the key.
 */
@Controller('internal')
export class MintController {
  constructor(private readonly mintService: MintService) {}

  @Post('mint')
  @Public()
  @UseGuards(ServiceTokenGuard)
  @HttpCode(HttpStatus.OK)
  mint(@Body() body: MintRequestDto) {
    return this.mintService.mint(body);
  }
}
