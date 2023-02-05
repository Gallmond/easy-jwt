"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = require("jsonwebtoken");
const node_crypto_1 = require("node:crypto");
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
    issuer = 'easy-jwt';
    accessTokenOptions = { expiresIn: SECONDS.hour };
    refreshTokenOptions = { expiresIn: SECONDS.week };
    accessTokenValidationCheckFunctions = [];
    refreshTokenValidationCheckFunctions = [];
    returnsSubjectFunction;
    constructor(options) {
        this.secret = options.secret;
        this.audience = (options.audience ?? this.audience);
        this.issuer = (options.issuer ?? this.issuer);
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
    refreshTokenValidation = (func) => {
        this.refreshTokenValidationCheckFunctions.push(func);
    };
    getJid = () => {
        return (0, node_crypto_1.randomBytes)(16).toString('hex');
    };
    createAccessToken = (subject, customPayload = {}) => {
        const payload = {
            ...customPayload,
            type: TOKEN_TYPES.access,
        };
        const expiresIn = this.accessTokenOptions.expiresIn;
        const { audience, issuer } = this;
        const jwtid = this.getJid();
        return (0, jsonwebtoken_1.sign)(payload, this.secret, {
            expiresIn, audience, issuer, jwtid, subject
        });
    };
    createRefreshToken = (subject, customPayload = {}) => {
        const payload = {
            ...customPayload,
            type: TOKEN_TYPES.refresh,
        };
        const expiresIn = this.refreshTokenOptions.expiresIn;
        const { audience, issuer } = this;
        const jwtid = this.getJid();
        return (0, jsonwebtoken_1.sign)(payload, this.secret, {
            expiresIn, audience, issuer, jwtid, subject
        });
    };
    decode = (jwt) => {
        return (0, jsonwebtoken_1.decode)(jwt, { complete: true });
    };
    createTokens = (subject, customPayload = {}) => {
        return {
            accessToken: this.createAccessToken(subject, customPayload),
            refreshToken: this.createRefreshToken(subject, customPayload),
            expiresIn: this.accessTokenOptions.expiresIn
        };
    };
    verifyJwt = (jwt) => {
        const payload = (0, jsonwebtoken_1.verify)(jwt, this.secret);
        // check if the token is revoked or fails custom validation check
        this.accessTokenValidationCheckFunctions.forEach(func => {
            console.log('running func');
            if (!func(jwt, payload)) {
                console.log('throwing');
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
        this.refreshTokenValidationCheckFunctions.forEach(func => {
            if (!func(refreshToken, payload)) {
                throw new Error('refreshToken is invalid');
            }
        });
        const { sub } = payload;
        // delete the required claims. They'll be remade
        delete payload.type;
        delete payload.iss;
        delete payload.sub;
        delete payload.aud;
        delete payload.exp;
        delete payload.nbf;
        delete payload.iat;
        delete payload.jti;
        if (typeof sub !== 'string') {
            throw new Error('Subject malformed');
        }
        return this.createAccessToken(sub, payload);
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
