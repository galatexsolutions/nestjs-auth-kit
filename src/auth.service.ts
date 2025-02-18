import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { OtpService } from './services/otp.service';
import { ForgotPasswordService } from './services/forgot-password.service';

@Injectable()
export class AuthService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly otpService: OtpService,
        private readonly forgotPasswordService: ForgotPasswordService,
    ) {}

    async login(user: any) {
        const payload = { email: user.email, sub: user.userId };
        return {
            access_token: this.jwtService.sign(payload),
        };
    }

    async validateGoogleUser(profile: any) {
        // Validate or create user from Google profile
        return { email: profile.emails[0].value, userId: profile.id };
    }

    async validateFacebookUser(profile: any) {
        // Validate or create user from Facebook profile
        return { email: profile.emails[0].value, userId: profile.id };
    }

    async sendOtp(email: string) {
        return this.otpService.generateOtp(email);
    }

    async verifyOtp(email: string, otp: string) {
        return this.otpService.verifyOtp(email, otp);
    }

    async resetPassword(email: string, otp: string, newPassword: string) {
        return this.forgotPasswordService.resetPassword(email, otp, newPassword);
    }
}
