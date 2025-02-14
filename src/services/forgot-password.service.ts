import { Injectable } from '@nestjs/common';
import { OtpService } from './otp.service';

@Injectable()
export class ForgotPasswordService {
    constructor(private readonly otpService: OtpService) {}

    async requestPasswordReset(email: string): Promise<string> {
        const otp = await this.otpService.generateOtp(email);
        console.log(`Password reset OTP for ${email}: ${otp}`);
        return 'OTP sent to registered email.';
    }

    async resetPassword(email: string, otp: string, newPassword: string): Promise<string> {
        const isOtpValid = await this.otpService.verifyOtp(email, otp);
        if (!isOtpValid) {
            throw new Error('Invalid or expired OTP');
        }
        console.log(`Password reset for ${email}, new password: ${newPassword}`);
        return 'Password has been reset successfully.';
    }
}
