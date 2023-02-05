import { type JwtPayload, type Jwt } from 'jsonwebtoken';
import { JWTString, ValidationCheckFunction, UserGetter, SECONDS, EasyJWTOptions } from './types';
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
    createTokens: (subject: string, customPayload?: JwtPayload) => {
        accessToken: string;
        refreshToken: string;
        expiresIn: SECONDS;
    };
    verifyJwt: (jwt: string) => JwtPayload;
    refreshJwt: (refreshToken: string) => string;
    accessTokenValidation: (func: ValidationCheckFunction) => void;
    refreshTokenValidation: (func: ValidationCheckFunction) => void;
    decode: (jwt: JWTString) => Jwt | null;
    getsModel<T>(func: UserGetter<T>): void;
    getModel<T>(jwt: JWTString): T;
    private getJid;
    private getSigningOptions;
    private createAccessToken;
    private createRefreshToken;
    private customValidation;
    private clearPayloadForDuplication;
}
export default EasyJWT;
//# sourceMappingURL=index.d.ts.map