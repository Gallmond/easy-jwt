import { sign, verify, type JwtPayload, type Jwt, decode } from 'jsonwebtoken'
import {randomBytes} from 'node:crypto'

interface ExpiryOption{
    expiresIn?: number
}

interface EasyJWTOptions{
    secret: string,
    audience?: string
    issuer?: string
    accessToken?: ExpiryOption,
    refreshToken?: ExpiryOption
}

type JWTString = string

type ValidationCheckFunction = (jwt: JWTString, payload: JwtPayload) => boolean

type UserGetter<T> = (jwt: JWTString, payload: JwtPayload) => T

enum SECONDS{
    hour = 60 * 60,
    day = 60 * 60 * 24,
    week = 60 * 60 * 24 * 7,
}

enum TOKEN_TYPES{
    access = 'access_token',
    refresh = 'refresh_token',
}

class EasyJWT{

    secret: string
    audience = 'easy-jwt'
    issuer = 'easy-jwt'
    accessTokenOptions = {
        expiresIn: SECONDS.hour
    }
    refreshTokenOptions = {
        expiresIn: SECONDS.week
    }

    accessTokenValidationCheckFunctions: ValidationCheckFunction[] = []
    accessTokenRevokedCheckFunctions: ValidationCheckFunction[] = []
    refreshTokenRevokedCheckFunctions: ValidationCheckFunction[] = []

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

    accessTokenValidation = (func: ValidationCheckFunction) => {
        this.accessTokenValidationCheckFunctions.push(func)
    }

    accessTokenRevokedWhen = (func: ValidationCheckFunction) => {
        this.accessTokenRevokedCheckFunctions.push(func)
    }

    refreshTokenRevokedWhen = (func: ValidationCheckFunction) => {
        this.refreshTokenRevokedCheckFunctions.push(func)
    }

    private getJid = () => {
        return randomBytes(16).toString('hex')
    }

    private createAccessToken = (subject: string, customPayload: JwtPayload = {}): string => {
        const payload = {
            ...customPayload,
            type: TOKEN_TYPES.access,
        }

        const expiresIn = this.accessTokenOptions.expiresIn
        const {audience, issuer} = this
        const jwtid = this.getJid()

        return sign(payload, this.secret, {
            expiresIn, audience, issuer, jwtid, subject
        })
    }

    private createRefreshToken = (subject: string, customPayload: JwtPayload = {}) => {
        const payload = {
            ...customPayload,
            type: TOKEN_TYPES.refresh,
        }

        const expiresIn = this.refreshTokenOptions.expiresIn
        const {audience, issuer} = this
        const jwtid = this.getJid()

        return sign(payload, this.secret, {
            expiresIn, audience, issuer, jwtid, subject
        })
    }

    decode = (jwt: JWTString): Jwt | null => {
        return decode(jwt, {complete: true})
    }

    createTokens = (subject: string, customPayload: JwtPayload = {}) => {
        return {
            accessToken: this.createAccessToken( subject, customPayload ),
            refreshToken: this.createRefreshToken( subject, customPayload ),
            expiresIn: this.accessTokenOptions.expiresIn
        }
    }

    verifyJwt = (jwt: string) => {
        const payload = verify(jwt, this.secret) as JwtPayload

        const checkFunctions = [
            ...this.accessTokenRevokedCheckFunctions,
            ...this.accessTokenValidationCheckFunctions
        ]

        // check if the token is revoked or fails custom validation check
        checkFunctions.forEach(func => {
            if(!func(jwt, payload)){
                throw new Error('accessToken is invalid')
            }
        })

        return payload
    }

    refreshJwt = (refreshToken: string) => {
        const payload = verify(refreshToken, this.secret) as JwtPayload

        if(payload.type !== TOKEN_TYPES.refresh){
            throw new Error('accessToken used as refreshToken')
        }

        // check if the token is revoked
        this.refreshTokenRevokedCheckFunctions.forEach(func => {
            if(!func(refreshToken, payload)){
                throw new Error('refreshToken is invalid')
            }
        })

        const { sub }= payload

        // delete the required claims. They'll be remade
        delete payload.type
        delete payload.iss
        delete payload.sub
        delete payload.aud
        delete payload.exp
        delete payload.nbf
        delete payload.iat
        delete payload.jti

        if(typeof sub !== 'string'){
            throw new Error('Subject malformed')
        }

        return this.createAccessToken(sub, payload)
    }

    getsModel<T>(func: UserGetter<T>){
        this.returnsSubjectFunction = func
    }

    getModel<T>(jwt: JWTString){
        if(!this.returnsSubjectFunction){
            throw new Error('call getsModel first`')
        }

        const payload = this.verifyJwt(jwt) as JwtPayload

        return this.returnsSubjectFunction(jwt, payload) as T
    }

}

export default EasyJWT