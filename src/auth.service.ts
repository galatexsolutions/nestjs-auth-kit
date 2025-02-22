import {Inject, Injectable} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { OtpService } from './services/otp.service';
import { ForgotPasswordService } from './services/forgot-password.service';
import { AUTH_OPTIONS } from "./constants/auth.constants";
import { AuthOptions } from "./interfaces/auth-options.interface";
import { RegisterDto } from './dto/register.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly otpService: OtpService,
        private readonly forgotPasswordService: ForgotPasswordService,
        @Inject(AUTH_OPTIONS) private readonly authOptions: AuthOptions,
        @InjectRepository(User) private readonly userRepository: Repository<User>,
    ) {}

    async register(registerDto: RegisterDto) {
        const { email, password, firstName, lastName } = registerDto;
        // Add logic to create a new user
        const user = this.userRepository.create({
            email,
            password,
            firstName,
            lastName,
        });

        return this.userRepository.save(user);
    }
    
    async login(user: any) {
        const payload = { email: user.email, sub: user.userId };
        return {
            access_token: this.jwtService.sign(payload, {
                secret: this.authOptions.jwtSecret,
                expiresIn: this.authOptions.jwtExpiration,
            }),
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
