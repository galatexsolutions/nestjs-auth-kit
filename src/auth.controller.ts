import { Controller, Get, Post, Body, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('login')
    async login(@Body() loginDto: any) {
        return this.authService.login(loginDto);
    }

    @Get('google')
    async googleLogin(@Req() req: any) {
        return this.authService.validateGoogleUser(req.user);
    }

    @Get('facebook')
    async facebookLogin(@Req() req: any) {
        return this.authService.validateFacebookUser(req.user);
    }

    @Post('otp')
    async sendOtp(@Body('email') email: string) {
        return this.authService.sendOtp(email);
    }

    @Post('otp/verify')
    async verifyOtp(@Body('email') email: string, @Body('otp') otp: string) {
        return this.authService.verifyOtp(email, otp);
    }

    @Post('password-reset')
    async resetPassword(
        @Body('email') email: string,
        @Body('otp') otp: string,
        @Body('newPassword') newPassword: string,
    ) {
        return this.authService.resetPassword(email, otp, newPassword);
    }

    @Get('me')
    @UseGuards(JwtAuthGuard)
    async getProfile(@Req() req: any) {
        return req.user;
    }

    @Get('admin')
    @UseGuards(JwtAuthGuard, RolesGuard)
    @Roles('admin')
    getAdminData() {
        return { message: 'Admin data' };
    }
}
