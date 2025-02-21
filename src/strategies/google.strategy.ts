import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { AuthService } from '../auth.service';
import { Inject } from '@nestjs/common';
import { AuthOptions } from '../interfaces/auth-options.interface';
import {AUTH_OPTIONS} from "../constants/auth.constants";

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
    constructor(
        private readonly authService: AuthService,
        @Inject(AUTH_OPTIONS) private readonly authOptions: AuthOptions,
    ) {
        super({
            clientID: authOptions.socialAuth?.google?.clientId,
            clientSecret: authOptions.socialAuth?.google?.clientSecret,
            callbackURL: 'http://localhost:3000/auth/google/callback',
            scope: ['email', 'profile'],
        });
    }

    async validate(accessToken: string, refreshToken: string, profile: any, done: VerifyCallback) {
        const user = await this.authService.validateGoogleUser(profile);
        done(null, user);
    }
}
