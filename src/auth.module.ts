import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { OtpService } from './services/otp.service';
import { ForgotPasswordService } from './services/forgot-password.service';

@Module({
    imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
            secret: process.env.JWT_SECRET,
            signOptions: { expiresIn: process.env.JWT_EXPIRATION || '1h' },
        }),
    ],
    providers: [
        AuthService,
        JwtStrategy,
        GoogleStrategy,
        FacebookStrategy,
        JwtAuthGuard,
        RolesGuard,
        OtpService,
        ForgotPasswordService,
    ],
    controllers: [AuthController],
    exports: [JwtAuthGuard, RolesGuard, AuthService],
})
export class AuthModule {}
