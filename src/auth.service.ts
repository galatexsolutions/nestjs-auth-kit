import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto'
import { RegisterDto } from './dto/register.dto'
import { ForgotPasswordDto } from './dto/forgot-password.dto'
import { OtpDto } from './dto/otp.dto'
import { SocialLoginDto } from './dto/social-login.dto'
import { UserEntity } from '../entities/user.entity';

@Injectable()
export class AuthService {
    private otpStore = new Map<string, string>(); // In-memory OTP storage

    constructor(
        private readonly jwtService: JwtService
    ) {}

    async register(dto: RegisterDto): Promise<{ accessToken: string }> {
        // Simulate user registration
        const user = new UserEntity(dto.email, dto.password);
        return { accessToken: this.generateJwt(user) };
    }

    async login(dto: LoginDto): Promise<{ accessToken: string }> {
        // Simulate login logic
        if (dto.email !== 'test@example.com' || dto.password !== 'password') {
            throw new UnauthorizedException('Invalid credentials');
        }
        const user = new UserEntity(dto.email, dto.password);
        return { accessToken: this.generateJwt(user) };
    }

    async socialLogin(dto: SocialLoginDto): Promise<{ accessToken: string }> {
        // Handle social login (Google, Facebook, etc.)
        return { accessToken: this.generateJwt(new UserEntity(dto.email, 'social-login')) };
    }

    async requestPasswordReset(dto: ForgotPasswordDto): Promise<string> {
        const otp = this.generateOtp(dto.email);
        console.log(`OTP for ${dto.email}: ${otp}`);
        return 'OTP sent to email';
    }

    async resetPassword(dto: OtpDto): Promise<string> {
        if (!this.verifyOtp(dto.email, dto.otp)) {
            throw new BadRequestException('Invalid OTP');
        }
        return 'Password reset successful';
    }

    private generateJwt(user: UserEntity): string {
        return this.jwtService.sign({ email: user.email }, { secret: process.env.JWT_SECRET || 'default_secret' });
    }

    private generateOtp(email: string): string {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        this.otpStore.set(email, otp);
        setTimeout(() => this.otpStore.delete(email), 300000); // OTP expires in 5 mins
        return otp;
    }

    private verifyOtp(email: string, otp: string): boolean {
        return this.otpStore.get(email) === otp;
    }
}
