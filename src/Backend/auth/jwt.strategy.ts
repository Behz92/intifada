import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Extract JWT from Bearer token
      ignoreExpiration: false, // Reject expired tokens
      secretOrKey: 'yourSecretKey', // Use your JWT secret from .env
    });
  }

  // This method is automatically called after the token is validated
  async validate(payload: any) {
    // The payload contains the data from the JWT token
    return { userId: payload.id, email: payload.email, role: payload.role };
  }
}
