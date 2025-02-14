import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { SocialAuthService } from './services/social-auth.service';
import { OtpService } from './services/otp.service';
import { ForgotPasswordService } from './services/forgot-password.service';

@Module({
    imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
            secret: process.env.JWT_SECRET || 'default_secret',
            signOptions: { expiresIn: '1h' },
        }),
    ],
    controllers: [AuthController],
    providers: [
        AuthService,
        JwtStrategy,
        GoogleStrategy,
        FacebookStrategy,
        JwtAuthGuard,
        SocialAuthService,
        OtpService,
        ForgotPasswordService,
    ],
    exports: [AuthService, JwtAuthGuard, SocialAuthService, OtpService, ForgotPasswordService],
})
export class AuthModule {}
