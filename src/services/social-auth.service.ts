import { Injectable } from '@nestjs/common';

@Injectable()
export class SocialAuthService {
    async handleGoogleLogin(user: any) {
        return { message: 'Google login successful', user };
    }

    async handleFacebookLogin(user: any) {
        return { message: 'Facebook login successful', user };
    }
}
