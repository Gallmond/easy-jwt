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
        // given - configs exist 
        const options = {secret, audience}

        // when - we create new instance
        const inst = new EasyJwt(options)
        
        // then - it is created with no issues
        expect(inst).toBeInstanceOf(EasyJwt)
    })

    test('Can create tokens', async () => {
        // given - an instance with relevant configs
        const twoDaysInSeconds = 60 * 60 * 24 * 2
        const inst = new EasyJwt({secret, audience, accessToken: {expiresIn: twoDaysInSeconds}})
        
        // when - we create tokens
        const subject = 'user-id-123'
        const {accessToken, expiresIn, refreshToken} = inst.createTokens(subject, {
            foo: 'bar'
        })
        
        // then - tokens are returned
        looksLikeJWT(accessToken)
        looksLikeJWT(refreshToken)
        expect(expiresIn).toBe(twoDaysInSeconds)
    })

    test('Can validate created tokens', async () => {
        // given - generated tokens
        const subject = 'user-id-123'
        const inst = new EasyJwt({secret, audience})
        const {accessToken} = inst.createTokens(subject, {
            foo: 'bar'
        })
        
        // when - we try to verify the access token
        const validated = inst.verifyJwt(accessToken)

        // then - the decided payload is returned with no error
        expect(validated.foo).toBe('bar')
    })

    test('Can refresh token', async () => {
        // given - an existing set of tokens
        const subject = 'user-id-123'
        const inst = new EasyJwt({secret, audience})
        const {accessToken, refreshToken} = inst.createTokens(subject, {
            foo: 'bar'
        })
        
        // advance time by 30:01 so we can check the times have changed
        const thirtyMinutesAndOneSecondLater = new Date( new Date().valueOf() + (60 * 30 * 1000) + 1000 )
        jest.useFakeTimers().setSystemTime(thirtyMinutesAndOneSecondLater)

        // when - we try to get a new access token by using the refresh token
        const newAccessToken = inst.refreshJwt( refreshToken )
        
        // then - a new access token with new exp payload but same data payload is returned
        const firstTokenData = inst.decode(accessToken) as Jwt
        const firstPayload = firstTokenData.payload as JwtPayload
        
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
        // given - an instance with custom validation logic and two tokens
        const subject = 'user-id-123'
        const inst = new EasyJwt({secret, audience})
        inst.accessTokenValidation((jwt, payload) => {
            return payload.foo === 'bar'
        })

        const firstTokens = inst.createTokens(subject, {foo: 'bar'})
        const secondTokens = inst.createTokens(subject, {foo: 'fizz'})

        // when - we try to validate the tokens
        const firstValid = inst.verifyJwt(firstTokens.accessToken)
        expect(typeof firstValid).toBe('object')
        
        // then - the expected failure occurs
        expect(() => {
            inst.verifyJwt(secondTokens.accessToken)
        }).toThrow('access_token is invalid')
    })

    test('Can use custom validation for refresh tokens', async () => {
        // given - custom refresh token validation logic
        const subject = 'user-id-123'
        const invalidRefreshTokens: string[] = []
        const inst = new EasyJwt({secret, audience})
        inst.refreshTokenValidation((jwt) => {
            return !invalidRefreshTokens.includes(jwt)
        })
        const {refreshToken} = inst.createTokens(subject, {foo: 'bar'})
        invalidRefreshTokens.push(refreshToken)

        // when - we try to validate a token that we know is in valid
        const attemptRefresh = () => {
            inst.refreshJwt(refreshToken)
        }

        // then - the expected error occurs
        expect(attemptRefresh).toThrow('refresh_token is invalid')
    })

    test('throw when trying to use consumer getter before its defined', () => {
        // given - an instance that has not yet had the custom model getter defined
        const subject = 'user-123'
        const inst = new EasyJwt({secret, audience})
        const { accessToken } = inst.createTokens(subject)
        
        // when - we try to use the model getter
        const attemptGetModel = () => inst.getModel<unknown>( accessToken )

        // then - the expected error is thrown
        expect(attemptGetModel).toThrow('call getsModel first')
    })

    test('consumer defined getter function async', async () => {
        // given - a user model, user instance, store of users, and custom getter
        class User{
            id: string
            name: string
            constructor(id: string, name: string){
                this.id = id
                this.name = name
            }
        }
        const bob = new User('123', 'Bob bobson')
        const userDatabase: Record<string, User> = { [bob.id]: bob }

        // when - we define an async getter
        const inst = new EasyJwt({secret}) 
        inst.getsModel<Promise<User>>(async (jwt, payload) => {
            if(!payload.sub) throw new Error('Not a user token')

            return userDatabase[payload.sub] ?? undefined
        })

        // then - we can await the getter
        const { accessToken } = inst.createTokens( bob.id )
        const retrievedBob = await inst.getModel<Promise<User>>( accessToken )

        expect(retrievedBob).toBeInstanceOf(User)
        expect(retrievedBob).toBe(bob)
    })

    test('consumer defined getter function', () => {
        // given - a user model, user instance, store of users, and custom getter
        class User{
            id: string
            name: string
            constructor(id: string, name: string){
                this.id = id
                this.name = name
            }
        }
        const bob = new User('123', 'Bob bobson')
        const userDatabase: Record<string, User> = { [bob.id]: bob }

        const inst = new EasyJwt({secret})

        inst.getsModel<User | undefined>((jwt, payload) => {
            if(!payload.sub) throw new Error('Not a user token')

            return userDatabase[ payload.sub ] ?? undefined
        })

        // when - we try to use the getter
        const { accessToken } = inst.createTokens( bob.id )
        const retrievedModel = inst.getModel<User>( accessToken )

        const noUserToken = inst.createTokens( 'foobar' ).accessToken

        // then - the expected model is returned (or not) as expected
        expect(retrievedModel).toBeInstanceOf(User)
        expect(retrievedModel).toBe(bob)

        const missingModel = inst.getModel<User>(noUserToken)
        expect(missingModel).toBeUndefined()
    })

})