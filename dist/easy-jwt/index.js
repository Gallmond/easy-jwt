"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = require("jsonwebtoken");
const node_crypto_1 = require("node:crypto");
const enums_1 = require("./enums");
const exceptions_1 = require("./exceptions");
class EasyJWT {
    secret;
    audience = 'easy-jwt';
    issuer = 'easy-jwt';
    accessTokenOptions = { expiresIn: enums_1.SECONDS.hour };
    refreshTokenOptions = { expiresIn: enums_1.SECONDS.week };
    accessTokenValidationChecks = [];
    refreshTokenValidationChecks = [];
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
    createTokens = (subject, customPayload = {}) => {
        return {
            accessToken: this.createAccessToken(subject, customPayload),
            refreshToken: this.createRefreshToken(subject, customPayload),
            expiresIn: this.accessTokenOptions.expiresIn
        };
    };
    verifyJwt = async (jwt) => {
        const payload = (0, jsonwebtoken_1.verify)(jwt, this.secret);
        // check if the token is revoked or fails custom validation check
        await this.customValidation(jwt, payload);
        return payload;
    };
    refreshJwt = async (refreshToken) => {
        const payload = (0, jsonwebtoken_1.verify)(refreshToken, this.secret);
        if (payload.type !== enums_1.TOKEN_TYPES.refresh) {
            throw new exceptions_1.EasyJWTTypeError('accessToken used as refreshToken');
        }
        // check if the token is revoked
        await this.customValidation(refreshToken, payload);
        const { sub } = payload;
        // delete the required claims. They'll be remade
        this.clearPayloadForDuplication(payload);
        if (typeof sub !== 'string') {
            throw new exceptions_1.EasyJWTSubjectError('Subject malformed');
        }
        return this.createAccessToken(sub, payload);
    };
    accessTokenValidation = (func) => {
        this.accessTokenValidationChecks.push(func);
    };
    refreshTokenValidation = (func) => {
        this.refreshTokenValidationChecks.push(func);
    };
    decode = (jwt) => {
        return (0, jsonwebtoken_1.decode)(jwt, { complete: true });
    };
    getsModel(func) {
        this.returnsSubjectFunction = func;
    }
    async getModel(jwt) {
        if (!this.returnsSubjectFunction) {
            throw new exceptions_1.EasyJWTGetModelError('call getsModel first`');
        }
        const payload = await this.verifyJwt(jwt);
        return this.returnsSubjectFunction(jwt, payload);
    }
    getJid = () => {
        return (0, node_crypto_1.randomBytes)(16).toString('hex');
    };
    getSigningOptions = (subject, expiresIn) => {
        return {
            subject,
            expiresIn,
            audience: this.audience,
            issuer: this.issuer,
            jwtid: this.getJid()
        };
    };
    createAccessToken = (subject, customPayload = {}) => {
        return (0, jsonwebtoken_1.sign)({ ...customPayload, type: enums_1.TOKEN_TYPES.access }, this.secret, this.getSigningOptions(subject, this.accessTokenOptions.expiresIn));
    };
    createRefreshToken = (subject, customPayload = {}) => {
        return (0, jsonwebtoken_1.sign)({ ...customPayload, type: enums_1.TOKEN_TYPES.refresh }, this.secret, this.getSigningOptions(subject, this.refreshTokenOptions.expiresIn));
    };
    customValidation = async (jwt, payload) => {
        const functions = [];
        if (payload.type === enums_1.TOKEN_TYPES.access) {
            functions.push(...this.accessTokenValidationChecks);
        }
        if (payload.type === enums_1.TOKEN_TYPES.refresh) {
            functions.push(...this.refreshTokenValidationChecks);
        }
        const results = await Promise.all(functions.map(func => {
            return func(jwt, payload);
        }));
        results.forEach(result => {
            if (!result)
                throw new exceptions_1.EasyJWTValidationError(`${payload.type ?? 'token'} is invalid`);
        });
    };
    clearPayloadForDuplication(payload) {
        delete payload.type;
        delete payload.iss;
        delete payload.sub;
        delete payload.aud;
        delete payload.exp;
        delete payload.nbf;
        delete payload.iat;
        delete payload.jti;
    }
}
exports.default = EasyJWT;
