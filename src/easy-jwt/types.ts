import { JwtPayload } from 'jsonwebtoken'

export type JWTString = string

export type ValidationCheckFunction = (jwt: JWTString, payload: JwtPayload) => boolean | Promise<boolean>

export type UserGetter<T> = (jwt: JWTString, payload: JwtPayload) => T

export interface ExpiryOption{
    expiresIn?: number
}

export interface EasyJWTOptions{
    secret: string,
    audience?: string
    issuer?: string
    accessToken?: ExpiryOption,
    refreshToken?: ExpiryOption
}