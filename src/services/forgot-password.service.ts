import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { OtpService } from './otp.service';

@Injectable()
export class ForgotPasswordService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly otpService: OtpService,
    ) {}

    async resetPassword(email: string, otp: string, newPassword: string): Promise<void> {
        const isValidOtp = await this.otpService.verifyOtp(email, otp);
        if (!isValidOtp) {
            throw new NotFoundException('Invalid or expired OTP.');
        }

        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) {
            throw new NotFoundException('User not found.');
        }

        user.password = newPassword; // In a real app, hash the password before saving
        await this.userRepository.save(user);
    }
}
