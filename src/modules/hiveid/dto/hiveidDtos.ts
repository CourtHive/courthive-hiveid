export class HiveIDVerifyExistingDto {
  email: string = '';
  password: string = '';
}

export class HiveIDMagicLinkRequestDto {
  email: string = '';
}

export class HiveIDMagicLinkConsumeDto {
  code: string = '';
}
