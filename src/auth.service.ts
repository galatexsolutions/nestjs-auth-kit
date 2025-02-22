import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { OtpService } from './services/otp.service';
import { ForgotPasswordService } from './services/forgot-password.service';
import { AUTH_OPTIONS } from './constants/auth.constants';
import { AuthOptions } from './interfaces/auth-options.interface';
import { RegisterDto } from './dto/register.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';

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

        if (!password) {
            throw new Error('Password is required');
        }

        // Encrypt the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const user = this.userRepository.create({
            email,
            password: hashedPassword,
            firstName,
            lastName,
        });

        return this.userRepository.save(user);
    }
    
    async login(loginDto: LoginDto) {
        const { email, password } = loginDto;
        const user = await this.userRepository.findOne({ where: { email } });

        if (!user) {
            throw new Error('Account not found');
        }

        if (!password) {
            throw new Error('Password is required');
        }

        // Validate the password
        const isPasswordValid = await bcrypt.compare(password, user.password || '');

        if (!isPasswordValid) {
            throw new Error('Invalid credentials');
        }

        const payload = { email: user.email, sub: user.id };
        
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
