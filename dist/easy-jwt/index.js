"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = require("jsonwebtoken");
var SECONDS;
(function (SECONDS) {
    SECONDS[SECONDS["hour"] = 3600] = "hour";
    SECONDS[SECONDS["day"] = 86400] = "day";
    SECONDS[SECONDS["week"] = 604800] = "week";
})(SECONDS || (SECONDS = {}));
var TOKEN_TYPES;
(function (TOKEN_TYPES) {
    TOKEN_TYPES["access"] = "access_token";
    TOKEN_TYPES["refresh"] = "refresh_token";
})(TOKEN_TYPES || (TOKEN_TYPES = {}));
class EasyJWT {
    secret;
    audience = 'easy-jwt';
    accessTokenOptions = {
        expiresIn: SECONDS.hour
    };
    refreshTokenOptions = {
        expiresIn: SECONDS.week
    };
    accessTokenValidationCheckFunctions = [];
    accessTokenRevokedCheckFunctions = [];
    refreshTokenRevokedCheckFunctions = [];
    returnsSubjectFunction;
    constructor(options) {
        this.secret = options.secret;
        this.audience = (options.audience ?? this.audience);
        if (options.accessToken) {
            this.accessTokenOptions = {
                ...this.accessTokenOptions,
                ...options.accessToken
            };
        }
        if (options.refreshToken) {
            this.refreshTokenOptions = {
                ...this.refreshTokenOptions,
                ...options.refreshToken
            };
        }
    }
    accessTokenValidation = (func) => {
        this.accessTokenValidationCheckFunctions.push(func);
    };
    accessTokenRevokedWhen = (func) => {
        this.accessTokenRevokedCheckFunctions.push(func);
    };
    refreshTokenRevokedWhen = (func) => {
        this.refreshTokenRevokedCheckFunctions.push(func);
    };
    createAccessToken = (customPayload) => {
        const payload = {
            type: TOKEN_TYPES.access,
            exp: this.accessTokenOptions.expiresIn,
            ...customPayload
        };
        return (0, jsonwebtoken_1.sign)(payload, this.secret);
    };
    createRefreshToken = (customPayload) => {
        const payload = {
            type: TOKEN_TYPES.refresh,
            exp: this.refreshTokenOptions.expiresIn,
            ...customPayload
        };
        return (0, jsonwebtoken_1.sign)(payload, this.secret);
    };
    createTokens = (customPayload) => {
        return {
            accessToken: this.createAccessToken(customPayload),
            refreshToken: this.createRefreshToken(customPayload),
            expiresIn: this.accessTokenOptions.expiresIn
        };
    };
    verifyJwt = (jwt) => {
        const payload = (0, jsonwebtoken_1.verify)(jwt, this.secret);
        const checkFunctions = [
            ...this.accessTokenRevokedCheckFunctions,
            ...this.accessTokenValidationCheckFunctions
        ];
        // check if the token is revoked or fails custom validation check
        checkFunctions.forEach(func => {
            if (!func(jwt, payload)) {
                throw new Error('accessToken is invalid');
            }
        });
        return payload;
    };
    refreshJwt = (refreshToken) => {
        const payload = (0, jsonwebtoken_1.verify)(refreshToken, this.secret);
        if (payload.type !== TOKEN_TYPES.refresh) {
            throw new Error('accessToken used as refreshToken');
        }
        // check if the token is revoked
        this.refreshTokenRevokedCheckFunctions.forEach(func => {
            if (!func(refreshToken, payload)) {
                throw new Error('refreshToken is invalid');
            }
        });
        // delete payload.iss
        // delete payload.sub
        // delete payload.aud
        delete payload.exp;
        delete payload.nbf;
        delete payload.iat;
        delete payload.jti;
        return this.createAccessToken(payload);
    };
    getsModel(func) {
        this.returnsSubjectFunction = func;
    }
    getModel(jwt) {
        if (!this.returnsSubjectFunction) {
            throw new Error('call getsModel first`');
        }
        const payload = this.verifyJwt(jwt);
        return this.returnsSubjectFunction(jwt, payload);
    }
}
exports.default = EasyJWT;
