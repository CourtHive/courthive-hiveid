export class ModifyUserDto {
  email: string = '';
  roles?: string[];
  permissions?: string[];
  firstName?: string;
  lastName?: string;
  phone?: string;
  contactEmail?: string;
  [key: string]: any;
}
