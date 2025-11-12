import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { Role, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { UserService } from '../users/user.service';
import { AuthRegisterDTO } from './domain/dto/authRegister.dto';
import { CreateUserDTO } from '../users/domain/dto/createUser.dto';
import { AuthResetPasswordDTO } from './domain/dto/authResetPassword.dto';
import { ValidateTokenDTO } from './domain/dto/validateToken.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}

  async generateToken(user: User, expiresIn: string = '1d') {
    const payload = { sub: user.id, name: user.name };

    const options: JwtSignOptions = {
      expiresIn: expiresIn as any,
      audience: 'users',
      issuer: 'dnc_hotel',
    };

    return { access_token: await this.jwtService.signAsync(payload, options) };
  }

  async login({ email, password }: { email: string; password: string }) {
    const user = await this.userService.findByEmail(email);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Email or password is incorrect');
    }

    return await this.generateToken(user);
  }

  async register(body: AuthRegisterDTO) {
    if (!body.name || !body.email || !body.password) {
      throw new Error('Missing required fields');
    }
    const newUser: CreateUserDTO = {
      name: body.name,
      email: body.email,
      password: body.password,
      role: body.role || Role.USER,
    };

    const user = await this.userService.createUser(newUser);
    return await this.generateToken(user);
  }

  async resetPassword({ token, password }: AuthResetPasswordDTO) {
    const { valid, decoded } = await this.validateToken(token);

    if (!valid || !decoded)
      throw new UnauthorizedException('Invalid or expired token');

    const user = await this.userService.updateUser(Number(decoded.sub), {
      password,
    });

    return await this.generateToken(user);
  }

  async forgotPassword(email: string) {
    const user = await this.userService.findByEmail(email);
    console.log(user);

    if (!user) {
      throw new UnauthorizedException('Email not found');
    }

    const token = this.generateToken(user, '30m');
    return token;
  }

  async validateToken(token: string): Promise<ValidateTokenDTO> {
    try {
      const decoded = await this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_SECRET,
        issuer: 'dnc_hotel',
        audience: 'users',
      });

      return { valid: true, decoded };
    } catch (error) {
      return { valid: false, message: error.message };
    }
  }
}
