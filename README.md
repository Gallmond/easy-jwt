# easy-jwt-auth

A dead easy implementation of JWT as authentication.

## Simple usage

```js
// initialise EasyJWT with some definitions
const easyAuth = new EasyJWT({
  secret: 'my-application-secret'
  accessToken: { expiresIn: 60 * 60 * 24 },     // expires in a day
  refreshToken: { expiresIn: 60 * 60 * 24 * 7 } // expires in a week
})

// create token for a user
const {accessToken, expiresIn, refreshToken} = easyAuth.createTokens(
  currentUser.id,                       // this is the 'subject' of our JWT
  { employeeLevels: ['administrator'] } // these are any arbitrary custom claims
)

// this token can then later be verified like
const tokenPayload = easyAuth.verifyJwt( accessToken )
tokenPayload.employeeLevel // ['administrator']

// or refreshed like so
const newAccessToken = easyAuth.refreshJwt( refreshToken )

// the custom claims are automatically copied across
newAccessToken.employeeLevel // ['administrator']
```

## Advanced usage

We can add additional validation steps like so. 

The custom function should return true if the token *is* valid

```js
// any access tokens should have claim employeeLevel array containing 'administrator'
easyAuth.accessTokenValidation((jwt, payload) => {
  return payload.employeeLevel.includes('administrator')
})

// refresh tokens should *not* be revoked
easyAuth.refreshTokenValidation((jwt, payload) => {
  return RevokedTokensTable.where('token', '=', jwt).count() < 1
})
```

If we tell EasyJWT what the subject refers to, we can even use the tokens directly
to return your models

```ts
type ReturnsUser = Promise<User | undefined>

easyAuth.getsModel<ReturnsUser>(async (jwt, payload) => {
  return await UserTable.where('id', '=', payload.sub ).first() ?? undefined
})

const authorisedUser = await easyAuth.getModel<ReturnsUser>( accessToken )
```
