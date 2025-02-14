import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(private readonly jwtService: JwtService) {}

    async validateUser(email: string, password: string): Promise<any> {
        // Validate user from DB (this is a placeholder)
        if (email === 'test@example.com' && password === 'password') {
            return { email };
        }
        return null;
    }

    async login(user: any) {
        const payload = { email: user.email };
        return {
            access_token: this.jwtService.sign(payload),
        };
    }
}
