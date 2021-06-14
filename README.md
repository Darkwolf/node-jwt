# JSON Web Token
## Install
`npm i --save @darkwolf/jwt`
## Usage
```javascript
// ECMAScript
import JWT from '@darkwolf/jwt'
// CommonJS
const JWT = require('@darkwolf/jwt')

const jwt = new JWT({
  uid: 'PavelWolfDark',
  admin: true
}, {
  issuer: 'auth.darkwolf',
  subject: 'auth.darkwolf',
  expiresIn: 3600
})

const secretKey = 'Ave, Darkwolf!'
const signedToken = jwt.sign(secretKey)

const decodedToken = new JWT(signedToken)
const payload = decodedToken.verify(secretKey)
```
## [API Documentation](https://github.com/Darkwolf/node-jwt/blob/master/docs/API.md)
## Contact Me
#### GitHub: [@PavelWolfDark](https://github.com/PavelWolfDark)
#### Telegram: [@PavelWolfDark](https://t.me/PavelWolfDark)
#### Email: [PavelWolfDark@gmail.com](mailto:PavelWolfDark@gmail.com)
