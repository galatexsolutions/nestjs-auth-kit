import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { OtpEntity } from '../entities/otp.entity';
import * as otplib from 'otplib';

@Injectable()
export class OtpService {
    constructor(
        @InjectRepository(OtpEntity)
        private readonly otpRepository: Repository<OtpEntity>,
    ) {}

    async generateOtp(email: string): Promise<string> {
        const otp = otplib.authenticator.generate(email);
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // OTP expires in 5 minutes

        await this.otpRepository.save({ email, otp, expiresAt });
        return otp;
    }

    async verifyOtp(email: string, otp: string): Promise<boolean> {
        const otpRecord = await this.otpRepository.findOne({
            where: { email, otpCode: otp },
            order: { createdAt: 'DESC' },
        });

        if (!otpRecord || (otpRecord.expiresAt !== undefined && otpRecord.expiresAt < new Date())) {
            return false; // OTP is invalid or expired
        }

        return otplib.authenticator.verify({ token: otp, secret: email });
    }
}
