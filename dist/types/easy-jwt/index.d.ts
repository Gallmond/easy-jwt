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
    accessTokenValidation: (func: ValidationCheckFunction) => void;
    refreshTokenValidation: (func: ValidationCheckFunction) => void;
    private getJid;
    private getSigningOptions;
    private createAccessToken;
    private createRefreshToken;
    decode: (jwt: JWTString) => Jwt | null;
    createTokens: (subject: string, customPayload?: JwtPayload) => {
        accessToken: string;
        refreshToken: string;
        expiresIn: SECONDS;
    };
    private customValidation;
    verifyJwt: (jwt: string) => JwtPayload;
    refreshJwt: (refreshToken: string) => string;
    private clearPayloadForDuplication;
    getsModel<T>(func: UserGetter<T>): void;
    getModel<T>(jwt: JWTString): T;
}
export default EasyJWT;
//# sourceMappingURL=index.d.ts.map