import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Patch,
  Post,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthLoginDTO } from './domain/dto/authLogin.dto';
import { AuthRegisterDTO } from './domain/dto/authRegister.dto';
import { AuthResetPasswordDTO } from './domain/dto/authResetPassword.dto';
import { AuthForgotPasswordDTO } from './domain/dto/authForgotPassword.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() body: AuthLoginDTO) {
    return await this.authService.login(body);
  }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() body: AuthRegisterDTO) {
    return await this.authService.register(body);
  }

  @Patch('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() { token, password }: AuthResetPasswordDTO) {
    return await this.authService.resetPassword({ token, password });
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() { email }: AuthForgotPasswordDTO) {
    return await this.authService.forgotPassword(email);
  }
}
