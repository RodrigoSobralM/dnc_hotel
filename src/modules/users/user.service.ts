import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { User } from '@prisma/client';
import { CreateUserDTO } from './domain/dto/createUser.dto';
import { UpdateUserDTO } from './domain/dto/updateUser.dto';
import * as bcrypt from 'bcrypt';
import { userSelectFields } from '../prisma/utils/userSelectFields';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async createUser(body: CreateUserDTO): Promise<User> {
    body.password = await this.cryptPassword(body.password);
    return await this.prisma.user.create({
      data: body,
      select: userSelectFields,
    });
  }

  async list() {
    return await this.prisma.user.findMany({
      select: userSelectFields,
    });
  }

  async show(id: number) {
    const user = await this.validateUser(id);
    return user;
  }

  async updateUser(id: number, body: UpdateUserDTO) {
    await this.validateUser(id);

    if (body.password) {
      body.password = await this.cryptPassword(body.password);
    }

    return await this.prisma.user.update({
      where: { id },
      data: body,
      select: userSelectFields,
    });
  }

  async deleteUser(id: number) {
    await this.validateUser(id);

    return await this.prisma.user.delete({
      where: { id },
    });
  }

  async findByEmail(email: string) {
    return await this.prisma.user.findUnique({
      where: { email },
    });
  }

  private async validateUser(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: userSelectFields,
    });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    return user;
  }

  private async cryptPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 10);
  }
}
