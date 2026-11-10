import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req } from '@nestjs/common';

import { Audience } from 'src/common/auth/decorators/audience.decorator';
import { Public } from 'src/common/auth/decorators/public.decorator';
import { SetContactEmailDto } from 'src/modules/identity/dto/setContactEmail.dto';
import { HiveIDSignupDto } from './dto/hiveidSignup.dto';
import { HiveIDVerifyExistingDto, HiveIDMagicLinkRequestDto, HiveIDMagicLinkConsumeDto } from './dto/hiveidDtos';
import { HiveIDService } from './hiveid.service';

// Public HiveID surface. @Public: signup / verify-existing / magic-link request
// + consume. @Audience(['hiveid']): the authed /me projection + resend +
// contact-email (AuthGuard admits the token only when its `aud` includes
// 'hiveid'). The tournament routes (participations/claimable/claim) stay on CFS.
@Controller('auth/hiveid')
export class HiveIDController {
  constructor(private readonly hiveidService: HiveIDService) {}

  @Public()
  @Post('signup')
  @HttpCode(HttpStatus.OK)
  signup(@Body() body: HiveIDSignupDto, @Req() req?: any) {
    return this.hiveidService.signup(body, req?.headers?.['user-agent']);
  }

  @Public()
  @Post('verify-existing')
  @HttpCode(HttpStatus.OK)
  verifyExisting(@Body() body: HiveIDVerifyExistingDto, @Req() req?: any) {
    return this.hiveidService.verifyExisting(body, req?.headers?.['user-agent']);
  }

  @Public()
  @Post('magic-link')
  @HttpCode(HttpStatus.OK)
  requestMagicLink(@Body() body: HiveIDMagicLinkRequestDto) {
    return this.hiveidService.requestMagicLink(body?.email ?? '');
  }

  @Public()
  @Post('magic-link/consume')
  @HttpCode(HttpStatus.OK)
  consumeMagicLink(@Body() body: HiveIDMagicLinkConsumeDto, @Req() req?: any) {
    return this.hiveidService.consumeMagicLink(body?.code ?? '', req?.headers?.['user-agent']);
  }

  @Audience(['hiveid'])
  @Get('me')
  @HttpCode(HttpStatus.OK)
  getMe(@Req() req: any) {
    return this.hiveidService.getMe(req?.user?.userId);
  }

  @Audience(['hiveid'])
  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  resendVerification(@Req() req: any) {
    return this.hiveidService.resendVerification({
      userId: req?.user?.userId,
      email: req?.user?.email,
      firstName: req?.user?.firstName,
    });
  }

  @Audience(['hiveid'])
  @Post('me/contact-email')
  @HttpCode(HttpStatus.OK)
  setContactEmail(@Body() body: SetContactEmailDto, @Req() req: any) {
    return this.hiveidService.setContactEmail({
      userId: req?.user?.userId,
      email: req?.user?.email,
      firstName: req?.user?.firstName,
      contactEmail: body?.contactEmail ?? '',
    });
  }
}
