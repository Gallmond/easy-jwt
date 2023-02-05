import { type JwtPayload, type Jwt } from 'jsonwebtoken';
type JWTString = string;
type ValidationCheckFunction = (jwt: JWTString, payload: JwtPayload) => boolean;
type UserGetter<T> = (jwt: JWTString, payload: JwtPayload) => T;
declare enum SECONDS {
    hour = 3600,
    day = 86400,
    week = 604800
}
interface ExpiryOption {
    expiresIn?: number;
}
interface EasyJWTOptions {
    secret: string;
    audience?: string;
    issuer?: string;
    accessToken?: ExpiryOption;
    refreshToken?: ExpiryOption;
}
declare class EasyJWT {
    secret: string;
    audience: string;
    issuer: string;
    accessTokenOptions: {
        expiresIn: SECONDS;
    };
    refreshTokenOptions: {
        expiresIn: SECONDS;
    };
    accessTokenValidationCheckFunctions: ValidationCheckFunction[];
    refreshTokenValidationCheckFunctions: ValidationCheckFunction[];
    returnsSubjectFunction?: UserGetter<unknown>;
    constructor(options: EasyJWTOptions);
    accessTokenValidation: (func: ValidationCheckFunction) => void;
    refreshTokenValidation: (func: ValidationCheckFunction) => void;
    private getJid;
    private createAccessToken;
    private createRefreshToken;
    decode: (jwt: JWTString) => Jwt | null;
    createTokens: (subject: string, customPayload?: JwtPayload) => {
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