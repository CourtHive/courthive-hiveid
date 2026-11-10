// Global @nestjs/config wiring. Exposes the `app` (baseUrl for email links) and
// `email` (from-address) namespaces that the ResendAdapter + auth.service read
// via ConfigService. Coexists with the hand-rolled config/env.ts (which the pg
// pool + bootstrap use).

import { Module } from '@nestjs/common';
import { ConfigModule, registerAs } from '@nestjs/config';

const appConfig = registerAs('app', () => ({ baseUrl: process.env.APP_BASE_URL ?? '' }));
const emailConfig = registerAs('email', () => ({ from: process.env.EMAIL_FROM ?? '' }));

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true, load: [appConfig, emailConfig] })],
})
export class ConfigsModule {}
