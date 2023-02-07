import { sign, verify, type JwtPayload, type Jwt, decode } from 'jsonwebtoken'
import { randomBytes } from 'node:crypto'
import { SECONDS, TOKEN_TYPES } from './enums'
import {
    EasyJWTGetModelError,
    EasyJWTSubjectError,
    EasyJWTTypeError,
    EasyJWTValidationError
} from './exceptions'
import type {
    JWTString,
    ValidationCheckFunction,
    UserGetter,
    EasyJWTOptions,
} from './types'

class EasyJWT{
    secret: string
    audience = 'easy-jwt'
    issuer = 'easy-jwt'
    accessTokenOptions = { expiresIn: SECONDS.hour }
    refreshTokenOptions = { expiresIn: SECONDS.week }

    accessTokenValidationChecks: ValidationCheckFunction[] = []
    refreshTokenValidationChecks: ValidationCheckFunction[] = []

    returnsSubjectFunction?: UserGetter<unknown>

    constructor(options: EasyJWTOptions){
        this.secret = options.secret
        this.audience = (options.audience ?? this.audience)
        this.issuer = (options.issuer ?? this.issuer)

        if(options.accessToken){
            this.accessTokenOptions = {
                ...this.accessTokenOptions,
                ...options.accessToken
            }
        }

        if(options.refreshToken){
            this.refreshTokenOptions = {
                ...this.refreshTokenOptions,
                ...options.refreshToken
            }
        }
    }

    createTokens = (subject: string, customPayload: JwtPayload = {}) => {
        return {
            accessToken: this.createAccessToken( subject, customPayload ),
            refreshToken: this.createRefreshToken( subject, customPayload ),
            expiresIn: this.accessTokenOptions.expiresIn
        }
    }

    verifyJwt = async (jwt: string) => {
        const payload = verify(jwt, this.secret) as JwtPayload

        // check if the token is revoked or fails custom validation check
        await this.customValidation(jwt, payload)

        return payload
    }

    refreshJwt = async (refreshToken: string) => {
        const payload = verify(refreshToken, this.secret) as JwtPayload

        if(payload.type !== TOKEN_TYPES.refresh){
            throw new EasyJWTTypeError('accessToken used as refreshToken')
        }

        // check if the token is revoked
        await this.customValidation(refreshToken, payload)

        const { sub } = payload

        // delete the required claims. They'll be remade
        this.clearPayloadForDuplication(payload)

        if(typeof sub !== 'string'){
            throw new EasyJWTSubjectError('Subject malformed')
        }

        return this.createAccessToken(sub, payload)
    }
    
    accessTokenValidation = (func: ValidationCheckFunction) => {
        this.accessTokenValidationChecks.push(func)
    }

    refreshTokenValidation = (func: ValidationCheckFunction) => {
        this.refreshTokenValidationChecks.push(func)
    }

    decode = (jwt: JWTString): Jwt | null => {
        return decode(jwt, {complete: true})
    }

    getsModel<T>(func: UserGetter<T>){
        this.returnsSubjectFunction = func
    }

    async getModel<T>(jwt: JWTString){
        if(!this.returnsSubjectFunction){
            throw new EasyJWTGetModelError('call getsModel first`')
        }

        const payload = await this.verifyJwt(jwt) as JwtPayload

        return this.returnsSubjectFunction(jwt, payload) as T
    }
    
    private getJid = () => {
        return randomBytes(16).toString('hex')
    }

    private getSigningOptions = (subject: string, expiresIn: number) => {
        return {
            subject,
            expiresIn,
            audience: this.audience,
            issuer: this.issuer,
            jwtid: this.getJid()
        }
    }

    private createAccessToken = (
        subject: string,
        customPayload: JwtPayload = {},
    ): string => {
        return sign(
            { ...customPayload, type: TOKEN_TYPES.access },
            this.secret,
            this.getSigningOptions(subject, this.accessTokenOptions.expiresIn) 
        )
    }

    private createRefreshToken = (
        subject: string,
        customPayload: JwtPayload = {},
    ) => {
        return sign(
            { ...customPayload, type: TOKEN_TYPES.refresh },
            this.secret,
            this.getSigningOptions(subject, this.refreshTokenOptions.expiresIn)
        )
    }

    private customValidation = async (jwt: JWTString, payload: JwtPayload) => {
        const functions = []
        if(payload.type === TOKEN_TYPES.access){
            functions.push( ...this.accessTokenValidationChecks )
        } 
        if(payload.type === TOKEN_TYPES.refresh){
            functions.push( ...this.refreshTokenValidationChecks )
        }

        const results = await Promise.all(functions.map(func => {
            return func(jwt, payload)
        }))

        results.forEach(result => {
            if(!result) throw new EasyJWTValidationError(`${payload.type ?? 'token'} is invalid`)
        })
    }

    private clearPayloadForDuplication(payload: JwtPayload){
        delete payload.type
        delete payload.iss
        delete payload.sub
        delete payload.aud
        delete payload.exp
        delete payload.nbf
        delete payload.iat
        delete payload.jti
    }

}

export default EasyJWT