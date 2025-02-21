import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from '../auth.service';
import { AuthOptions } from '../interfaces/auth-options.interface';
import {AUTH_OPTIONS} from "../constants/auth.constants";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        private readonly authService: AuthService,
        @Inject(AUTH_OPTIONS) private readonly authOptions: AuthOptions,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: authOptions.jwtSecret,
        });
    }

    async validate(payload: any) {
        return { userId: payload.sub, email: payload.email };
    }
}
