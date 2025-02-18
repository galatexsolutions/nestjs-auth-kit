import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(private reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());
        if (!requiredRoles) {
            return true; // No roles specified, allow access
        }

        const request = context.switchToHttp().getRequest();
        const user = request.user;

        if (!user || !user.roles) {
            throw new ForbiddenException('Access denied: User has no roles assigned.');
        }

        const hasRole = requiredRoles.some((role: any) => user.roles.includes(role));
        if (!hasRole) {
            throw new ForbiddenException('Access denied: User does not have the required role.');
        }

        return true;
    }
}
