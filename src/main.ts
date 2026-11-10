// NestJS bootstrap for courthive-hiveid (the HiveID auth/identity provider).
//
// Logger config matches CFS / courthive-declarations so combined log
// aggregation reads uniformly. CORS is open for the browser auth routes
// (login/signup called from courthive-public + TMX). Post-cutover, nginx
// path-routes `^/(auth|account)/` here, so routes are mounted at root with
// NO global prefix — the path-routed cutover depends on it.

import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { json } from 'express';

import { AppModule } from './app.module';
import { loadEnv } from './config/env';

async function bootstrap() {
  const env = loadEnv();
  const app = await NestFactory.create(AppModule, { logger: ['fatal', 'error', 'warn', 'verbose', 'debug'] });

  app.enableCors({
    methods: ['GET', 'PUT', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-service-token'],
    origin: '*',
  });
  app.use(json({ limit: '2mb' }));
  app.enableShutdownHooks();

  await app.listen(env.port, '0.0.0.0');
  Logger.verbose(`courthive-hiveid listening on ${await app.getUrl()}`);
  Logger.verbose(`NODE_ENV=${env.nodeEnv}`);
}

bootstrap();
