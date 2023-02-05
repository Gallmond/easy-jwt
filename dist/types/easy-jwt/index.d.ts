import { JwtPayload } from 'jsonwebtoken';
interface ExpiryOption {
    expiresIn?: number;
}
interface EasyJWTOptions {
    secret: string;
    audience?: string;
    accessToken?: ExpiryOption;
    refreshToken?: ExpiryOption;
}
type JWTString = string;
type ValidationCheckFunction = (jwt: JWTString, payload: JwtPayload) => boolean;
type UserGetter<T> = (jwt: JWTString, payload: JwtPayload) => T;
declare enum SECONDS {
    hour = 3600,
    day = 86400,
    week = 604800
}
declare class EasyJWT {
    secret: string;
    audience: string;
    accessTokenOptions: {
        expiresIn: SECONDS;
    };
    refreshTokenOptions: {
        expiresIn: SECONDS;
    };
    accessTokenValidationCheckFunctions: ValidationCheckFunction[];
    accessTokenRevokedCheckFunctions: ValidationCheckFunction[];
    refreshTokenRevokedCheckFunctions: ValidationCheckFunction[];
    returnsSubjectFunction?: UserGetter<unknown>;
    constructor(options: EasyJWTOptions);
    accessTokenValidation: (func: ValidationCheckFunction) => void;
    accessTokenRevokedWhen: (func: ValidationCheckFunction) => void;
    refreshTokenRevokedWhen: (func: ValidationCheckFunction) => void;
    private createAccessToken;
    private createRefreshToken;
    createTokens: (customPayload: JwtPayload) => {
        accessToken: string;
        refreshToken: string;
        expiresIn: SECONDS;
    };
    verifyJwt: (jwt: string) => JwtPayload;
    refreshJwt: (refreshToken: string) => string;
    getsModel<T>(func: UserGetter<T>): void;
    getModel<T>(jwt: JWTString): T;
}
export default EasyJWT;
//# sourceMappingURL=index.d.ts.map