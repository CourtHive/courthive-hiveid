export class AdminCreateUserDto {
  email: string = '';
  password?: string;
  contactEmail?: string;
  providerId?: string;
  providerRole?: string;
  firstName?: string;
  lastName?: string;
  phone?: string;
  roles?: string[];
  permissions?: string[];
  services?: string[];
}
