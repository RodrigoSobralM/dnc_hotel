import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthForgotPasswordDTO {
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;
}
