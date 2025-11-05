import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { Role, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { UserService } from '../users/user.service';
import { AuthRegisterDTO } from './domain/dto/authRegister.dto';
import { CreateUserDTO } from '../users/domain/dto/createUser.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}

  async generateToken(user: User) {
    const payload = { sub: user.id, name: user.name };

    const options: JwtSignOptions = {
      expiresIn: '1d',
      audience: 'users',
      issuer: 'dnc_hotel',
    };

    return { access_token: await this.jwtService.signAsync(payload, options) };
  }

  async login({ email, password }: { email: string; password: string }) {
    const user = await this.userService.findByEmail(email);

    if (!user || bcrypt.compareSync(password, user.password) === false) {
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
}
