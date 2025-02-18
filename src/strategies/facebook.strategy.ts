import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-facebook';
import { AuthService } from '../auth.service';
import { VerifyCallback } from 'passport-oauth2'; // Import VerifyCallback from passport-oauth2

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
    constructor(private readonly authService: AuthService) {
        super({
            clientID: process.env.FACEBOOK_CLIENT_ID,
            clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
            callbackURL: 'http://localhost:3000/auth/facebook/callback',
            profileFields: ['emails', 'name'], // Specify the fields you want to retrieve
        });
    }

    async validate(
        accessToken: string,
        refreshToken: string,
        profile: any,
        done: VerifyCallback, // Use VerifyCallback here
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
