import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {
  
  constructor(
    private jwt: JwtService,
    private authServie: AuthService
  ){}

  async canActivate(context: ExecutionContext):  Promise<boolean> {
    
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    
    if (!token) {
      throw new UnauthorizedException('No hay token en la peticion');
    }

    try {
      const payload = await this.jwt.verifyAsync<JwtPayload>(
        token, { secret: process.env.JWT_SEED }
        );

        const user = await this.authServie.findUserById(payload.id);

        if (!user) throw new UnauthorizedException('User does not exists');
        if (!user.isActive) throw new UnauthorizedException('User is not active');

      console.log(payload);

      // 💡 We're assigning the payload to the request object here
      // so that we can access it in our route handlers
      request['user'] = user;

    } catch (error) {
      throw new UnauthorizedException('Token no puede ser verificado');
    }
    
    

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
