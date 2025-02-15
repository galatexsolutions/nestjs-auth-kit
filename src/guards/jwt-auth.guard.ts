import { Injectable, ExecutionContext, CanActivate, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard implements CanActivate {
    constructor(private jwtService: JwtService) {}

    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest();
        const token = request.headers.authorization?.split(' ')[1];

        if (!token) {
            throw new UnauthorizedException('Missing token');
        }

        try {
            request.user = this.jwtService.verify(token);
            return true;
        } catch (error) {
            throw new UnauthorizedException('Invalid token');
        }
    }
}
