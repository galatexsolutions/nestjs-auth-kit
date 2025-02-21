export interface AuthOptions {
    jwtSecret: string;
    jwtExpiration: string;
    socialAuth: {
        google: {
            clientId: string;
            clientSecret: string;
        };
        facebook: {
            clientId: string;
            clientSecret: string;
        };
    };
}
