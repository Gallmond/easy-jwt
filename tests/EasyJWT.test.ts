import { Jwt, JwtPayload } from 'jsonwebtoken'
import EasyJwt from '../src/index'

const looksLikeJWT = (jwt: string) => {
    expect(typeof jwt).toBe('string')
    expect(jwt.split('.').length).toBe(3)
}

describe('EasyJWT', () => {
    const secret = 'foobar123'
    const audience = 'test-audience'

    test('Can instantiate', async () => {
        const inst = new EasyJwt({secret, audience})
        expect(inst).toBeInstanceOf(EasyJwt)
    })

    test('Can create tokens', async () => {
        const twoDaysInSeconds = 60 * 60 * 24 * 2

        const subject = 'user-id-123'

        const inst = new EasyJwt({secret, audience, accessToken: {expiresIn: twoDaysInSeconds}})
        const {accessToken, expiresIn, refreshToken} = inst.createTokens(subject, {
            foo: 'bar'
        })
        looksLikeJWT(accessToken)
        looksLikeJWT(refreshToken)
        expect(expiresIn).toBe(twoDaysInSeconds)
    })

    test('Can validate created tokens', async () => {

        const subject = 'user-id-123'

        const inst = new EasyJwt({secret, audience})
        const {accessToken, expiresIn, refreshToken} = inst.createTokens(subject, {
            foo: 'bar'
        })

        const validated = inst.verifyJwt(accessToken)
        expect(validated.foo).toBe('bar')
    })

    test('Can refresh token', async () => {

        const subject = 'user-id-123'

        const inst = new EasyJwt({secret, audience})
        const {accessToken, expiresIn, refreshToken} = inst.createTokens(subject, {
            foo: 'bar'
        })

        const firstTokenData = inst.decode(accessToken) as Jwt
        const firstPayload = firstTokenData.payload as JwtPayload

        // advance time by 30:01 so we can check the times have changed
        const thirtyMinutesAndOneSecondLater = new Date( new Date().valueOf() + (60 * 30 * 1000) + 1000 )
        jest.useFakeTimers().setSystemTime(thirtyMinutesAndOneSecondLater)

        const newAccessToken = inst.refreshJwt( refreshToken )
        const secondTokenData = inst.decode(newAccessToken) as Jwt
        const secondPayload = secondTokenData.payload as JwtPayload

        // the jwt specific parts should be new
        expect(firstPayload.jti).not.toBe(secondPayload.jti)
        expect(firstPayload.exp).not.toBe(secondPayload.exp)
        expect(firstPayload.iat).not.toBe(secondPayload.iat)

        // the user specific parts should be the same
        expect(firstPayload.type).toBe(secondPayload.type)
        expect(firstPayload.foo).toBe(secondPayload.foo)
        expect(firstPayload.aud).toBe(secondPayload.aud)
        expect(firstPayload.iss).toBe(secondPayload.iss)
        expect(firstPayload.sub).toBe(secondPayload.sub)

        jest.useRealTimers()
    })

    test('Can use custom validation', async () => {

        const subject = 'user-id-123'

        const inst = new EasyJwt({secret, audience})
        inst.accessTokenValidation((jwt, payload) => {
            return payload.foo === 'bar'
        })

        const firstTokens = inst.createTokens(subject, {foo: 'bar'})
        const secondTokens = inst.createTokens(subject, {foo: 'fizz'})

        const firstValid = inst.verifyJwt(firstTokens.accessToken)
        expect(typeof firstValid).toBe('object')

        expect(() => {
            inst.verifyJwt(secondTokens.accessToken)
        }).rejects.toThrow('accessToken is invalid')
    })

    test('Can use custom accessToken revoke check', async () => {

        const subject = 'user-id-123'

        const revokedTokensDatabase: Record<string, boolean> = {}

        const inst = new EasyJwt({secret, audience})
        inst.accessTokenRevokedWhen((jwt, payload) => {
            if(revokedTokensDatabase[ jwt ]){
                return true
            }

            return false
        })

        const {accessToken} = inst.createTokens(subject, {foo: 'bar'})
        revokedTokensDatabase[ accessToken ] = true

        expect(() => {
            inst.verifyJwt( accessToken )
        }).rejects.toThrow('accessToken is invalid')

    })

    test('Can use custom refreshToken revoke check', async () => {})

})