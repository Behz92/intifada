import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> {
    // Get roles defined for the route
    const roles = this.reflector.get<string[]>(ROLES_KEY, context.getHandler());
    if (!roles) {
      return true; // Allow access if no roles are specified
    }

    // Extract the user from the request
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('Access denied: User not authenticated');
    }

    // Check if the user's role is in the allowed roles
    const hasRole = roles.includes(user.role);
    if (!hasRole) {
      throw new ForbiddenException(`Access denied: Requires one of the following roles: ${roles.join(', ')}`);
    }

    return true; // Grant access if role matches
  }
}
