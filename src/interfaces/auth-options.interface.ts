export interface AuthOptions {
    jwtSecret: string;
    enableSocialLogin?: boolean;
    enableOtp?: boolean;
    enableRBAC?: boolean;
}
