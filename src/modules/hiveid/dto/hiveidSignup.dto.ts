export class HiveIDFederationIdDto {
  provider: string = '';
  externalId: string = '';
}

export class HiveIDSignupDto {
  email: string = '';
  firstName: string = '';
  lastName: string = '';
  federationIds?: HiveIDFederationIdDto[];
  birthDate?: string;
  sex?: string;
  provider?: string;
}
