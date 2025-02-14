import { Injectable } from '@nestjs/common';

@Injectable()
export class OtpService {
    private otpStore = new Map<string, string>();

    async generateOtp(email: string): Promise<string> {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        this.otpStore.set(email, otp);
        setTimeout(() => this.otpStore.delete(email), 300000); // OTP expires in 5 minutes
        return otp;
    }

    async verifyOtp(email: string, otp: string): Promise<boolean> {
        return this.otpStore.get(email) === otp;
    }
}
