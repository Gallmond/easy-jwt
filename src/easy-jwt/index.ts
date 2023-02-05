import { sign, verify, type JwtPayload, type Jwt, decode } from 'jsonwebtoken'
import {randomBytes} from 'node:crypto'
import { EasyJWTGetModelError, EasyJWTSubjectError, EasyJWTTypeError, EasyJWTValidationError } from './exceptions'
import {
    JWTString,
    ValidationCheckFunction,
    UserGetter,
    SECONDS,
    TOKEN_TYPES,
    EasyJWTOptions,
} from './types'


class EasyJWT{
    secret: string
    audience = 'easy-jwt'
    issuer = 'easy-jwt'
    accessTokenOptions = { expiresIn: SECONDS.hour }
    refreshTokenOptions = { expiresIn: SECONDS.week }

    accessTokenValidationCheckFunctions: ValidationCheckFunction[] = []
    refreshTokenValidationCheckFunctions: ValidationCheckFunction[] = []

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

    refreshTokenValidation = (func: ValidationCheckFunction) => {
        this.refreshTokenValidationCheckFunctions.push(func)
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

    private createAccessToken = (subject: string, customPayload: JwtPayload = {}): string => {
        return sign(
            { ...customPayload, type: TOKEN_TYPES.access },
            this.secret,
            this.getSigningOptions(subject, this.accessTokenOptions.expiresIn) 
        )
    }

    private createRefreshToken = (subject: string, customPayload: JwtPayload = {}) => {
        return sign(
            { ...customPayload, type: TOKEN_TYPES.refresh },
            this.secret,
            this.getSigningOptions(subject, this.refreshTokenOptions.expiresIn)
        )
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

    private customValidation = (jwt: JWTString, payload: JwtPayload) => {
        const functions = []
        if(payload.type === TOKEN_TYPES.access) functions.push( ...this.accessTokenValidationCheckFunctions )
        if(payload.type === TOKEN_TYPES.refresh) functions.push( ...this.refreshTokenValidationCheckFunctions )

        functions.forEach(func => {
            if(!func(jwt, payload)){
                throw new EasyJWTValidationError(`${payload.type} is invalid`)
            }
        })

    }

    verifyJwt = (jwt: string) => {
        const payload = verify(jwt, this.secret) as JwtPayload

        // check if the token is revoked or fails custom validation check
        this.customValidation(jwt, payload)

        return payload
    }

    refreshJwt = (refreshToken: string) => {
        const payload = verify(refreshToken, this.secret) as JwtPayload

        if(payload.type !== TOKEN_TYPES.refresh){
            throw new EasyJWTTypeError('accessToken used as refreshToken')
        }

        // check if the token is revoked
        this.customValidation(refreshToken, payload)

        const { sub } = payload

        // delete the required claims. They'll be remade
        this.clearPayloadForDuplication(payload)

        if(typeof sub !== 'string'){
            throw new EasyJWTSubjectError('Subject malformed')
        }

        return this.createAccessToken(sub, payload)
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

    getsModel<T>(func: UserGetter<T>){
        this.returnsSubjectFunction = func
    }

    getModel<T>(jwt: JWTString){
        if(!this.returnsSubjectFunction){
            throw new EasyJWTGetModelError('call getsModel first`')
        }

        const payload = this.verifyJwt(jwt) as JwtPayload

        return this.returnsSubjectFunction(jwt, payload) as T
    }

}

export default EasyJWT