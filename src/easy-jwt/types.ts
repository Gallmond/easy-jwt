import { JwtPayload } from 'jsonwebtoken'

export type JWTString = string

export type ValidationCheckFunction = (jwt: JWTString, payload: JwtPayload) => boolean

export type UserGetter<T> = (jwt: JWTString, payload: JwtPayload) => T

export enum SECONDS{
    hour = 60 * 60,
    day = 60 * 60 * 24,
    week = 60 * 60 * 24 * 7,
}

export enum TOKEN_TYPES{
    access = 'access_token',
    refresh = 'refresh_token',
}

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