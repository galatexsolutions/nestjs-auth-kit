# 🛡️ NestJS Auth Kit

A modular authentication kit for NestJS providing JWT authentication, OAuth2 social login (Google, Facebook, etc.), OTP verification, and password reset functionality. 

[//]: # (Simplify authentication in your NestJS applications with NestJS Auth Kit. Install the package and start building secure applications today! 🎯)

---

## 🚀 Features
- ✅ **JWT-based authentication** (Access & Refresh tokens)
- ✅ **OAuth2 social login** (Google, Facebook, etc.)
- ✅ **OTP-based authentication** (Email or SMS-based)
- ✅ **Password reset via OTP**
- ✅ **Role-based access control (RBAC)**
- ✅ **Modular and scalable architecture**
- ✅ **Custom decorators for roles and authentication**
- ✅ **Integration with NestJS Guards & Interceptors**
- ✅ **Customizable authentication strategies**
- ✅ **Configurable environment variables**

---

## 📦 Installation

```sh
npm install nestjs-auth-kit
```

or with Yarn:

```sh
yarn add nestjs-auth-kit
```

---

## 🛠️ Setup & Usage

### 1️⃣ Import the `AuthModule` in `app.module.ts`

```ts

@Module({
    imports: [
        AuthModule.register({
            jwtSecret: process.env.JWT_SECRET,
            jwtExpiration: process.env.JWT_EXPIRATION || '1h',
            socialAuth: {
                google: {
                    clientId: process.env.GOOGLE_CLIENT_ID,
                    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
                },
                facebook: {
                    clientId: process.env.FACEBOOK_CLIENT_ID,
                    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
                },
            },
        }),
    ],
})
export class AppModule {}
```

---

### 2️⃣ Configure `.env` Variables

Make sure your environment variables are correctly set:

```env
JWT_SECRET=your_jwt_secret
JWT_EXPIRATION=1h
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
FACEBOOK_CLIENT_ID=your_facebook_client_id
FACEBOOK_CLIENT_SECRET=your_facebook_client_secret
OTP_EXPIRATION=300  # OTP expiry time in seconds
```

---

### 3️⃣ **Available Authentication Methods**
#### 🔹 **JWT Authentication**
Login and get a JWT token:

```ts
import { AuthService } from 'nestjs-auth-kit';

constructor(private authService: AuthService) {}

async login() {
  return this.authService.login({ email: 'user@example.com', password: 'password' });
}
```

#### 🔹 **OAuth2 Social Login**
Authenticate using Google:

```ts
import { SocialAuthService } from 'nestjs-auth-kit';

constructor(private socialAuthService: SocialAuthService) {}

async googleLogin(token: string) {
  return this.socialAuthService.validateGoogleUser(token);
}
```

#### 🔹 **OTP-based Authentication**
Generate an OTP:

```ts
import { OtpService } from 'nestjs-auth-kit';

constructor(private otpService: OtpService) {}

async sendOtp(email: string) {
  return this.otpService.generateOtp(email);
}
```

Verify OTP:

```ts
async verifyOtp(email: string, otp: string) {
  return this.otpService.verifyOtp(email, otp);
}
```

#### 🔹 **Password Reset via OTP**
```ts
import { ForgotPasswordService } from 'nestjs-auth-kit';

constructor(private forgotPasswordService: ForgotPasswordService) {}

async resetPassword(email: string, otp: string, newPassword: string) {
  return this.forgotPasswordService.resetPassword(email, otp, newPassword);
}
```

---

## 🔐 Role-Based Access Control (RBAC)

Use the `@Roles()` decorator to protect routes based on roles.

```ts
import { Controller, Get } from '@nestjs/common';
import { Roles } from 'nestjs-auth-kit';

@Controller('admin')
export class AdminController {
  @Get()
  @Roles('admin')
  getAdminData() {
    return { message: 'Admin data' };
  }
}
```

---

## 📜 API Endpoints

| Endpoint             | Method | Description |
|----------------------|--------|-------------|
| `/auth/login`       | `POST`  | User login |
| `/auth/register`    | `POST`  | User registration |
| `/auth/google`      | `GET`   | Google OAuth login |
| `/auth/facebook`    | `GET`   | Facebook OAuth login |
| `/auth/otp`         | `POST`  | OTP generation |
| `/auth/otp/verify`  | `POST`  | OTP verification |
| `/auth/password-reset` | `POST` | Reset password via OTP |
| `/auth/me`          | `GET`   | Get authenticated user info |

---

## ⚙️ Configuration Options

You can configure authentication options using `AuthModule.register()`.

```ts
AuthModule.register({
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiration: '1h',
  socialAuth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    },
    facebook: {
      clientId: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    },
  },
});
```

---

## 🏗️ Folder Structure

```
nestjs-auth-kit/
│── src/
│   ├── auth.module.ts
│   ├── auth.service.ts
│   ├── auth.controller.ts
│   ├── strategies/
│   │   ├── jwt.strategy.ts
│   │   ├── google.strategy.ts
│   │   ├── facebook.strategy.ts
│   ├── guards/
│   │   ├── jwt-auth.guard.ts
│   ├── decorators/
│   │   ├── roles.decorator.ts
│   ├── dto/
│   │   ├── login.dto.ts
│   │   ├── register.dto.ts
│   ├── interfaces/
│   │   ├── auth-options.interface.ts
│── package.json
│── index.ts
```

---

## 📄 License
MIT License © 2025 [Galatex Solutions](https://github.com/galatexsolutions)

---

## 🤝 Contribution Guidelines

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-branch`
3. Commit your changes: `git commit -m "Added new feature"`
4. Push to the branch: `git push origin feature-branch`
5. Open a pull request.

---

## 📬 Contact & Support

For issues, questions, or suggestions, feel free to open an issue on [GitHub](https://github.com/galatexsolutions/nestjs-auth-kit/issues).

---

🚀 **NestJS Auth Kit** is designed to simplify authentication in NestJS applications. Get started today! 🎯
