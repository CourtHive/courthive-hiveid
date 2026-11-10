import { Module } from '@nestjs/common';

import { PersonsClient } from './persons-client.service';

@Module({
  providers: [PersonsClient],
  exports: [PersonsClient],
})
export class PersonsClientModule {}
