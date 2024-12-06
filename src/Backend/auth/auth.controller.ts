import { Controller, Get, UseGuards, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Roles } from './decorators/roles.decorator'; 
import { AuthorizationGuard } from './guards/authorization.guards';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(
    @Body() body: { createDto: any; role: 'admin' | 'student' | 'instructor' },
  ) {
    const { createDto, role } = body;
    return await this.authService.registerUser(createDto, role);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() body: { email: string; password: string; role: 'admin' | 'student' | 'instructor' }) {
    const { email, password, role } = body;
    return await this.authService.login(email, password, role);
  }

  @UseGuards(AuthorizationGuard)
    @Get('dashboard')
    @Roles('admin') // Only admin users can access this route
    getDashboard() {
      return 'Welcome to the admin dashboard!';
    }
}
