// Core Module & Service
export * from './auth.module';
export * from './auth.service';
export * from './auth.controller';

// Strategies
export * from './strategies/jwt.strategy';
export * from './strategies/google.strategy';
export * from './strategies/facebook.strategy';

// Guards
export * from './guards/jwt-auth.guard';
export * from './guards/roles.guard';

// Decorators
export * from './decorators/roles.decorator';

// DTOs
export * from './dto/login.dto';
export * from './dto/register.dto';
export * from './dto/otp.dto';
export * from './dto/forgot-password.dto';

// Interfaces
export * from './interfaces/auth-options.interface';
