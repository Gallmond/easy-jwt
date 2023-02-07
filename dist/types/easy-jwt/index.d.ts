import { type JwtPayload, type Jwt } from 'jsonwebtoken';
import { SECONDS } from './enums';
import type { JWTString, ValidationCheckFunction, UserGetter, EasyJWTOptions } from './types';
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
    accessTokenValidationChecks: ValidationCheckFunction[];
    refreshTokenValidationChecks: ValidationCheckFunction[];
    returnsSubjectFunction?: UserGetter<unknown>;
    constructor(options: EasyJWTOptions);
    createTokens: (subject: string, customPayload?: JwtPayload) => {
        accessToken: string;
        refreshToken: string;
        expiresIn: SECONDS;
    };
    verifyJwt: (jwt: string) => Promise<JwtPayload>;
    refreshJwt: (refreshToken: string) => Promise<string>;
    accessTokenValidation: (func: ValidationCheckFunction) => void;
    refreshTokenValidation: (func: ValidationCheckFunction) => void;
    decode: (jwt: JWTString) => Jwt | null;
    getsModel<T>(func: UserGetter<T>): void;
    getModel<T>(jwt: JWTString): Promise<T>;
    private getJid;
    private getSigningOptions;
    private createAccessToken;
    private createRefreshToken;
    private customValidation;
    private clearPayloadForDuplication;
}
export default EasyJWT;
//# sourceMappingURL=index.d.ts.map