import { DynamicModule, Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { FacebookStrategy } from './strategies/facebook.strategy';
import { AuthOptions } from './interfaces/auth-options.interface';
import { OtpService } from './services/otp.service';
import { ForgotPasswordService } from './services/forgot-password.service';

@Module({})
export class AuthModule {
    static register(options: AuthOptions): DynamicModule {
        return {
            module: AuthModule,
            imports: [
                PassportModule.register({ defaultStrategy: 'jwt' }),
                JwtModule.register({
                    secret: options.jwtSecret,
                    signOptions: { expiresIn: options.jwtExpiration },
                }),
            ],
            providers: [
                AuthService,
                OtpService,
                ForgotPasswordService,
                JwtStrategy,
                GoogleStrategy,
                FacebookStrategy,
                {
                    provide: 'AUTH_OPTIONS',
                    useValue: options,
                },
            ],
            controllers: [AuthController],
            exports: [AuthService],
        };
    }
}
