// Always returns { ok: true } regardless of registration (enumeration defense).
export class ForgotPasswordDto {
  contactEmail: string = '';
}
