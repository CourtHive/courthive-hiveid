import { Module } from '@nestjs/common';

import { MintController } from './mint.controller';
import { MintService } from './mint.service';

// The internal SPLIT-token signer. JwtService is provided globally
// by the root JwtModule, so signJwt resolves it without a local import here.
@Module({
  controllers: [MintController],
  providers: [MintService],
})
export class MintModule {}
