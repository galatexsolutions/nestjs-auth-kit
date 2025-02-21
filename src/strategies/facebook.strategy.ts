import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-facebook';
import { AuthService } from '../auth.service';
import { AuthOptions } from '../interfaces/auth-options.interface';
import {AUTH_OPTIONS} from "../constants/auth.constants";
import { VerifyCallback } from 'passport-oauth2'; // Import VerifyCallback from passport-oauth2


@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
    constructor(
        private readonly authService: AuthService,
        @Inject(AUTH_OPTIONS) private readonly authOptions: AuthOptions,
    ) {
        super({
            clientID: authOptions.socialAuth?.facebook?.clientId,
            clientSecret: authOptions.socialAuth?.facebook?.clientSecret,
            callbackURL: 'http://localhost:3000/auth/facebook/callback',
            profileFields: ['emails', 'name'],
        });
    }

    async validate(
        accessToken: string,
        refreshToken: string,
        profile: any,
        done: VerifyCallback,
    ) {
        const { emails, name } = profile;
        const user = {
            email: emails[0].value,
            firstName: name.givenName,
            lastName: name.familyName,
            accessToken,
        };

        // Validate or create the user in your database
        const validatedUser = await this.authService.validateFacebookUser(user);
        done(null, validatedUser);
    }
}
