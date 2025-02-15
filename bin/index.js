#!/usr/bin/env node
import { execSync } from 'child_process';
import inquirer from 'inquirer';
import fs from 'fs';
import path from 'path';

// Locate the user's NestJS project directory
function findUserProjectRoot() {
    let currentDir = process.cwd();

    while (currentDir !== '/' && !fs.existsSync(path.join(currentDir, 'package.json'))) {
        currentDir = path.dirname(currentDir);
    }

    if (fs.existsSync(path.join(currentDir, 'package.json'))) {
        return currentDir;
    } else {
        console.error('❌ Error: Could not find a NestJS project. Please run this command inside a NestJS project.');
        process.exit(1);
    }
}

// Function to create files safely
function writeFileSafe(filePath, content) {
    if (fs.existsSync(filePath)) {
        console.log(`⚠️ File already exists: ${filePath}`);
    } else {
        fs.writeFileSync(filePath, content);
        console.log(`✅ Created: ${filePath}`);
    }
}

// Define CLI Questions
async function askQuestions() {
    return await inquirer.prompt([
        {
            type: 'list',
            name: 'architecture',
            message: 'Which architecture are you using?',
            choices: ['Monolithic', 'Microservices'],
        },
        {
            type: 'confirm',
            name: 'enableSocialLogin',
            message: 'Enable social login (Google, Facebook, etc.)?',
        },
        {
            type: 'confirm',
            name: 'enableOtp',
            message: 'Enable OTP authentication?',
        },
        {
            type: 'confirm',
            name: 'enableRbac',
            message: 'Enable Role-Based Access Control (RBAC)?',
        },
        {
            type: 'list',
            name: 'database',
            message: 'Which database are you using?',
            choices: ['Prisma', 'TypeORM', 'Mongoose'],
        },
        {
            type: 'input',
            name: 'jwtSecret',
            message: 'Enter JWT secret key:',
            default: 'your_secret_key',
        },
        {
            type: 'input',
            name: 'jwtExpiry',
            message: 'Enter JWT expiry time:',
            default: '1h',
        },
    ]);
}

// Generate Authentication Module in the Correct Project
async function generateAuthModule(answers) {
    const projectRoot = findUserProjectRoot();
    const authDir = path.join(projectRoot, 'src', 'auth');

    if (!fs.existsSync(authDir)) {
        fs.mkdirSync(authDir, { recursive: true });
        fs.mkdirSync(`${authDir}/strategies`, { recursive: true });
    }

    // Create `auth.module.ts`
    writeFileSafe(
        path.join(authDir, 'auth.module.ts'),
        `
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './strategies/jwt.strategy';
${answers.enableSocialLogin ? "import { SocialAuthService } from './social-auth.service';" : ''}
${answers.enableOtp ? "import { OtpService } from './otp.service';" : ''}
${answers.enableRbac ? "import { RolesGuard } from './roles.guard';" : ''}

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: '${answers.jwtSecret}',
      signOptions: { expiresIn: '${answers.jwtExpiry}' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy ${answers.enableSocialLogin ? ', SocialAuthService' : ''} ${answers.enableOtp ? ', OtpService' : ''} ${answers.enableRbac ? ', RolesGuard' : ''}],
  exports: [AuthService],
})
export class AuthModule {}
        `
    );

    // Create `auth.service.ts`
    writeFileSafe(
        path.join(authDir, 'auth.service.ts'),
        `
import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  validateUser(username: string, password: string): boolean {
    return username === 'admin' && password === 'password';
  }
}
        `
    );

    // Create `auth.controller.ts`
    writeFileSafe(
        path.join(authDir, 'auth.controller.ts'),
        `
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  login(@Body() body) {
    return this.authService.validateUser(body.username, body.password);
  }
}
        `
    );

    // Create `jwt.strategy.ts`
    writeFileSafe(
        path.join(`${authDir}/strategies`, 'jwt.strategy.ts'),
        `
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: '${answers.jwtSecret}',
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, username: payload.username };
  }
}
        `
    );

    // Create `social-auth.service.ts` if social login is enabled
    if (answers.enableSocialLogin) {
        writeFileSafe(
            path.join(authDir, 'social-auth.service.ts'),
            `
import { Injectable } from '@nestjs/common';

@Injectable()
export class SocialAuthService {
  loginWithGoogle(token: string) {
    return { message: 'Google login successful', token };
  }
}
            `
        );
    }

    // Create `otp.service.ts` if OTP is enabled
    if (answers.enableOtp) {
        writeFileSafe(
            path.join(authDir, 'otp.service.ts'),
            `
import { Injectable } from '@nestjs/common';

@Injectable()
export class OtpService {
  generateOtp() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }
}
            `
        );
    }

    // Create `roles.guard.ts` if RBAC is enabled
    if (answers.enableRbac) {
        writeFileSafe(
            path.join(authDir, 'guards/roles.guard.ts'),
            `
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';

@Injectable()
export class RolesGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    return request.user && request.user.role === 'admin';
  }
}
            `
        );
    }

    console.log('🚀 Authentication module successfully generated inside your NestJS project!');
}

// Main function
async function main() {
    console.log('🔧 NestJS Auth Kit CLI Setup');
    const answers = await askQuestions();
    await generateAuthModule(answers);
}

main();
