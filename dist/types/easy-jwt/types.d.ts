import { JwtPayload } from 'jsonwebtoken';
export type JWTString = string;
export type ValidationCheckFunction = (jwt: JWTString, payload: JwtPayload) => boolean;
export type UserGetter<T> = (jwt: JWTString, payload: JwtPayload) => T;
export declare enum SECONDS {
    hour = 3600,
    day = 86400,
    week = 604800
}
export declare enum TOKEN_TYPES {
    access = "access_token",
    refresh = "refresh_token"
}
export interface ExpiryOption {
    expiresIn?: number;
}
export interface EasyJWTOptions {
    secret: string;
    audience?: string;
    issuer?: string;
    accessToken?: ExpiryOption;
    refreshToken?: ExpiryOption;
}
//# sourceMappingURL=types.d.ts.map