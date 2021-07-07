'use strict'
const {
  constants: {
    RSA_PKCS1_PSS_PADDING,
    RSA_PSS_SALTLEN_DIGEST
  },
  createHmac,
  createSign,
  createVerify
} = require('crypto')
const {
  ObjectCreate,
  ObjectDefineProperties,
  ObjectEntries,
  FunctionPrototypeBind,
  FunctionPrototypeSymbolHasInstance,
  Symbol,
  SymbolToStringTag,
  Error,
  RangeError,
  TypeError,
  NumberMAX_SAFE_INTEGER,
  NumberIsInteger,
  MathFloor,
  DateNow,
  DatePrototypeGetTime,
  String,
  StringPrototypeSlice,
  StringPrototypeSplit,
  ArrayIsArray,
  ArrayPrototypeEvery,
  ArrayPrototypeForEach,
  ArrayPrototypeMap,
  JSONParse,
  JSONStringify,
  ReflectSetPrototypeOf,
  InstancesIsDate,
  InstancesIsUint8Array,
  PrimitivesIsString,
  TypesIsPlainObject,
  TypesToIntegerOrInfinity
} = require('@darkwolf/primordials')
const {
  encodeText: Base64URLEncodeText,
  decodeText: Base64URLDecodeText,
  encodeToString: Base64URLEncodeToString,
  decodeFromString: Base64URLDecodeFromString
} = require('@darkwolf/base64url')

const headerSymbol = Symbol('header')
const payloadSymbol = Symbol('payload')
const signatureSymbol = Symbol('signature')
const encodedHeaderSymbol = Symbol('encodedHeader')
const encodedPayloadSymbol = Symbol('encodedPayload')
const encodedSignatureSymbol = Symbol('encodedSignature')
const encodeHeaderSymbol = Symbol('encodeHeader')
const encodePayloadSymbol = Symbol('encodePayload')
const encodeSignatureSymbol = Symbol('encodeSignature')
const encodeUnsecuredSymbol = Symbol('encodeUnsecured')
const encodeSymbol = Symbol('encode')
const createSignatureSymbol = Symbol('createSignature')
const verifySignatureSymbol = Symbol('verifySignature')

const TOKEN_TYPE = 'JWT'

const ALGORITHM = 'HS256'
const NONE = 'none'

const DELIMITER_CHAR = '.'

const ERR_INVALID_TOKEN = 'INVALID_TOKEN'
const ERR_INVALID_HEADER = 'INVALID_HEADER'
const ERR_INVALID_TOKEN_TYPE = 'INVALID_TOKEN_TYPE'
const ERR_INVALID_ALGORITHM = 'INVALID_ALGORITHM'
const ERR_INVALID_PAYLOAD = 'INVALID_PAYLOAD'
const ERR_INVALID_ISSUER = 'INVALID_ISSUER'
const ERR_INVALID_SUBJECT = 'INVALID_SUBJECT'
const ERR_INVALID_AUDIENCE = 'INVALID_AUDIENCE'
const ERR_INVALID_EXPIRATION_DATE = 'INVALID_EXPIRATION_DATE'
const ERR_INVALID_NOT_BEFORE_DATE = 'INVALID_NOT_BEFORE_DATE'
const ERR_INVALID_ISSUED_AT = 'INVALID_ISSUED_AT'
const ERR_INVALID_JWT_ID = 'INVALID_JWT_ID'
const ERR_SIGNATURE_REQUIRED = 'SIGNATURE_REQUIRED'
const ERR_INVALID_SIGNATURE = 'INVALID_SIGNATURE'
const ERR_TOKEN_EXPIRED = 'TOKEN_EXPIRED'
const ERR_TOKEN_NOT_ACTIVE = 'TOKEN_NOT_ACTIVE'

const getAlgorithms = () => [
  'HS256',
  'HS384',
  'HS512',
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512',
  'none'
]

const algorithmPrefixLookup = {
  HS256: 'HS',
  HS384: 'HS',
  HS512: 'HS',
  RS256: 'RS',
  RS384: 'RS',
  RS512: 'RS',
  ES256: 'ES',
  ES384: 'ES',
  ES512: 'ES',
  PS256: 'PS',
  PS384: 'PS',
  PS512: 'PS',
  none: null
}
ReflectSetPrototypeOf(algorithmPrefixLookup, null)

const algorithmBitsLookup = {
  HS256: 256,
  HS384: 384,
  HS512: 512,
  RS256: 256,
  RS384: 384,
  RS512: 512,
  ES256: 256,
  ES384: 384,
  ES512: 512,
  PS256: 256,
  PS384: 384,
  PS512: 512,
  none: null
}
ReflectSetPrototypeOf(algorithmBitsLookup, null)

const validateTokenType = value => {
  if (!PrimitivesIsString(value)) {
    throw new TypeError('The type must be a string')
  }
  if (value !== TOKEN_TYPE) {
    throw new TypeError('The type must be "JWT"')
  }
}

const isAlgorithm = value => PrimitivesIsString(value) && algorithmBitsLookup[value] !== undefined

const validateAlgorithm = value => {
  if (!PrimitivesIsString(value)) {
    throw new TypeError('The algorithm must be a string')
  }
  if (algorithmBitsLookup[value] == null) {
    throw new TypeError('The algorithm must be "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384" or "PS512"')
  }
}

const toAlgorithm = value => {
  if (value === undefined) {
    return ALGORITHM
  }
  if (!PrimitivesIsString(value)) {
    throw new TypeError('The algorithm must be a string')
  }
  if (algorithmBitsLookup[value] === undefined) {
    throw new TypeError('The algorithm must be "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" or "none"')
  }
  return value
}

const validateSignature = value => {
  if (!InstancesIsUint8Array(value)) {
    throw new TypeError('The signature must be an instance of Uint8Array')
  }
  if (!value.length) {
    throw new RangeError('The length of the signature must be greater than zero')
  }
}

const validateToken = value => {
  if (!PrimitivesIsString(value)) {
    throw new TypeError('The token must be a string')
  }
  if (!value.length) {
    throw new RangeError('The length of the token must be greater than zero')
  }
}

const getUnixTimestamp = () => MathFloor(DateNow() / 1e3)

const toUnixTimestamp = value => {
  if (InstancesIsDate(value)) {
    value = DatePrototypeGetTime(value) / 1e3
  }
  value = TypesToIntegerOrInfinity(value)
  if (value < 0) {
    throw new RangeError('The timestamp must be greater than or equal to zero')
  }
  if (value > NumberMAX_SAFE_INTEGER) {
    throw new RangeError('The timestamp must be less than or equal to the maximum safe integer')
  }
  return value
}

const toMaxAge = value => {
  value = TypesToIntegerOrInfinity(value)
  if (value < 0) {
    throw new RangeError('The maxAge must be greater than or equal to zero')
  }
  if (value > NumberMAX_SAFE_INTEGER) {
    throw new RangeError('The maxAge must be less than or equal to the maximum safe integer')
  }
  return value
}

const createSignatureHS = (bits, data, secretKey) =>
  createHmac(`sha${bits}`, secretKey)
    .update(data)
    .digest()

const verifySignatureHS = (bits, data, secretKey, signature) => {
  const sign = createSignatureHS(bits, data, secretKey)
  const {length} = sign
  if (signature.length !== length) {
    return false
  }
  for (let i = 0; i < length; i++) {
    if (signature[i] !== sign[i]) {
      return false
    }
  }
  return true
}

const createSignatureRS = (bits, data, privateKey) =>
  createSign(`RSA-SHA${bits}`)
    .update(data)
    .sign(privateKey)

const verifySignatureRS = (bits, data, publicKey, signature) =>
  createVerify(`RSA-SHA${bits}`)
    .update(data)
    .verify(publicKey, signature)

const createSignatureES = (bits, data, privateKey) =>
  createSign(`RSA-SHA${bits}`)
    .update(data)
    .sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363'
    })

const verifySignatureES = (bits, data, publicKey, signature) =>
  createVerify(`RSA-SHA${bits}`)
    .update(data)
    .verify({
      key: publicKey,
      dsaEncoding: 'ieee-p1363'
    }, signature)

const createSignaturePS = (bits, data, privateKey) =>
  createSign(`RSA-SHA${bits}`)
    .update(data)
    .sign({
      key: privateKey,
      padding: RSA_PKCS1_PSS_PADDING,
      saltLength: RSA_PSS_SALTLEN_DIGEST
    })

const verifySignaturePS = (bits, data, publicKey, signature) =>
  createVerify(`RSA-SHA${bits}`)
    .update(data)
    .verify({
      key: publicKey,
      padding: RSA_PKCS1_PSS_PADDING,
      saltLength: RSA_PSS_SALTLEN_DIGEST
    }, signature)

const signerLookup = {
  HS: createSignatureHS,
  RS: createSignatureRS,
  ES: createSignatureES,
  PS: createSignaturePS
}
ReflectSetPrototypeOf(signerLookup, null)

const verifierLookup = {
  HS: verifySignatureHS,
  RS: verifySignatureRS,
  ES: verifySignatureES,
  PS: verifySignaturePS
}
ReflectSetPrototypeOf(verifierLookup, null)

const _createSignature = (algorithm, data, key) => {
  const prefix = algorithmPrefixLookup[algorithm]
  const bits = algorithmBitsLookup[algorithm]
  const signer = signerLookup[prefix]
  return signer(bits, data, key)
}
const createSignature = (algorithm, data, key) => {
  validateAlgorithm(algorithm)
  return _createSignature(algorithm, data, key)
}

const _verifySignature = (algorithm, data, key, signature) => {
  const prefix = algorithmPrefixLookup[algorithm]
  const bits = algorithmBitsLookup[algorithm]
  const verifier = verifierLookup[prefix]
  return verifier(bits, data, key, signature)
}
const verifySignature = (algorithm, data, key, signature) => {
  validateAlgorithm(algorithm)
  validateSignature(signature)
  return _verifySignature(algorithm, data, key, signature)
}

class JWTError extends Error {
  constructor(code, message) {
    super(message)
    this.code = code
  }
}

const isJWTError = FunctionPrototypeBind(FunctionPrototypeSymbolHasInstance, null, JWTError)

ObjectDefineProperties(JWTError.prototype, {
  name: {
    value: 'JWTError'
  }
})

const validateHeader = value => {
  if (!TypesIsPlainObject(value)) {
    throw new JWTError(ERR_INVALID_HEADER, 'The header must be a plain object')
  }
  const {
    typ: type,
    alg: algorithm
  } = value
  if (type !== undefined) {
    if (!PrimitivesIsString(type)) {
      throw new JWTError(ERR_INVALID_TOKEN_TYPE, 'The "typ" header parameter must be a string')
    }
    if (type !== TOKEN_TYPE) {
      throw new JWTError(ERR_INVALID_TOKEN_TYPE, 'The "typ" header parameter must be "JWT"')
    }
  }
  if (!PrimitivesIsString(algorithm)) {
    throw new JWTError(ERR_INVALID_ALGORITHM, 'The "alg" header parameter must be a string')
  }
  if (algorithmBitsLookup[algorithm] === undefined) {
    throw new JWTError(ERR_INVALID_ALGORITHM, 'The "alg" header parameter must be "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" or "none"')
  }
}

const validatePayload = value => {
  if (!TypesIsPlainObject(value)) {
    throw new JWTError(ERR_INVALID_PAYLOAD, 'The payload must be a plain object')
  }
  const {
    iss: issuer,
    sub: subject,
    aud: audience,
    exp: expirationDate,
    nbf: notBeforeDate,
    iat: issuedAt,
    jti: jwtId
  } = value
  if (issuer !== undefined && !PrimitivesIsString(issuer)) {
    throw new JWTError(ERR_INVALID_ISSUER, 'The "iss" claim must be a string')
  }
  if (subject !== undefined && !PrimitivesIsString(subject)) {
    throw new JWTError(ERR_INVALID_SUBJECT, 'The "sub" claim must be a string')
  }
  if (audience !== undefined && (
    !PrimitivesIsString(audience) ||
    !(ArrayIsArray(audience) && ArrayPrototypeEvery(audience, audience => PrimitivesIsString(audience)))
  )) {
    throw new JWTError(ERR_INVALID_AUDIENCE, 'The "aud" claim must be a string or an array of strings')
  }
  if (expirationDate !== undefined) {
    if (!NumberIsInteger(expirationDate)) {
      throw new JWTError(ERR_INVALID_EXPIRATION_DATE, 'The "exp" claim must be an integer')
    }
    if (expirationDate < 0) {
      throw new JWTError(ERR_INVALID_EXPIRATION_DATE, 'The "exp" claim must be greater than or equal to zero')
    }
    if (expirationDate > NumberMAX_SAFE_INTEGER) {
      throw new JWTError(ERR_INVALID_EXPIRATION_DATE, 'The "exp" claim must be less than or equal to the maximum safe integer')
    }
  }
  if (notBeforeDate !== undefined) {
    if (!NumberIsInteger(notBeforeDate)) {
      throw new JWTError(ERR_INVALID_NOT_BEFORE_DATE, 'The "nbf" claim must be an integer')
    }
    if (notBeforeDate < 0) {
      throw new JWTError(ERR_INVALID_NOT_BEFORE_DATE, 'The "nbf" claim must be greater than or equal to zero')
    }
    if (notBeforeDate > NumberMAX_SAFE_INTEGER) {
      throw new JWTError(ERR_INVALID_NOT_BEFORE_DATE, 'The "nbf" claim must be less than or equal to the maximum safe integer')
    }
  }
  if (issuedAt !== undefined) {
    if (!NumberIsInteger(issuedAt)) {
      throw new JWTError(ERR_INVALID_ISSUED_AT, 'The "iat" claim must be an integer')
    }
    if (issuedAt < 0) {
      throw new JWTError(ERR_INVALID_ISSUED_AT, 'The "iat" claim must be greater than or equal to zero')
    }
    if (issuedAt > NumberMAX_SAFE_INTEGER) {
      throw new JWTError(ERR_INVALID_ISSUED_AT, 'The "iat" claim must be less than or equal to the maximum safe integer')
    }
  }
  if (jwtId !== undefined && !PrimitivesIsString(jwtId)) {
    throw new JWTError(ERR_INVALID_JWT_ID, 'The "jti" claim must be a string')
  }
}

const _encodeHeader = header => Base64URLEncodeText(JSONStringify(header))
const encodeHeader = header => {
  validateHeader(header)
  return _encodeHeader(header)
}

const _encodePayload = payload => Base64URLEncodeText(JSONStringify(payload))
const encodePayload = payload => {
  validatePayload(payload)
  return _encodePayload(payload)
}

const _encodeSignature = signature => Base64URLEncodeToString(signature)
const encodeSignature = signature => {
  validateSignature(signature)
  return _encodeSignature(signature)
}

const _encodeUnsecured = (header, payload) => {
  const encodedHeader = _encodeHeader(header)
  const encodedPayload = _encodePayload(payload)
  return `${encodedHeader}${DELIMITER_CHAR}${encodedPayload}`
}
const encodeUnsecured = (header, payload) => {
  validateHeader(header)
  validatePayload(payload)
  return _encodeUnsecured(header, payload)
}

const _encode = (header, payload, signature) => {
  const {
    alg: algorithm
  } = header
  let result = _encodeUnsecured(header, payload)
  if (algorithm !== NONE) {
    const encodedSignature = _encodeSignature(signature)
    result += `${DELIMITER_CHAR}${encodedSignature}`
  }
  return result
}
const encode = (header, payload, signature) => {
  validateHeader(header)
  validatePayload(payload)
  const {
    alg: algorithm
  } = header
  if (algorithm !== NONE) {
    if (signature == null) {
      throw new JWTError(ERR_SIGNATURE_REQUIRED, 'The signature required')
    }
    validateSignature(signature)
  }
  return _encode(header, payload, signature)
}

const _decodeHeader = input => {
  let header
  try {
    header = JSONParse(Base64URLDecodeText(input))
  } catch (e) {
    throw new JWTError(ERR_INVALID_HEADER, e.message)
  }
  validateHeader(header)
  ReflectSetPrototypeOf(header, null)
  return header
}
const decodeHeader = input => {
  if (!PrimitivesIsString(input)) {
    throw new TypeError('The input must be a string')
  }
  if (!input.length) {
    throw new RangeError('The length of the input must be greater than zero')
  }
  return _decodeHeader(input)
}

const _decodePayload = input => {
  let payload
  try {
    payload = JSONParse(Base64URLDecodeText(input))
  } catch (e) {
    throw new JWTError(ERR_INVALID_PAYLOAD, e.message)
  }
  validatePayload(payload)
  ReflectSetPrototypeOf(payload, null)
  return payload
}
const decodePayload = input => {
  if (!PrimitivesIsString(input)) {
    throw new TypeError('The input must be a string')
  }
  if (!input.length) {
    throw new RangeError('The length of the input must be greater than zero')
  }
  return _decodePayload(input)
}

const _decodeSignature = input => {
  try {
    return Base64URLDecodeFromString(input)
  } catch (e) {
    throw new JWTError(ERR_INVALID_SIGNATURE, e.message)
  }
}
const decodeSignature = input => {
  if (!PrimitivesIsString(input)) {
    throw new TypeError('The input must be a string')
  }
  if (!input.length) {
    throw new RangeError('The length of the input must be greater than zero')
  }
  return _decodeSignature(input)
}

const _decodeUnsecured = (token, encoded) => {
  const [encodedHeader, encodedPayload] = StringPrototypeSplit(token, DELIMITER_CHAR, 2)
  if (!encodedHeader) {
    throw new JWTError(ERR_INVALID_TOKEN, 'The header required')
  }
  if (!encodedPayload) {
    throw new JWTError(ERR_INVALID_TOKEN, 'The payload required')
  }
  const header = _decodeHeader(encodedHeader)
  const payload = _decodePayload(encodedPayload)
  const result = {
    header,
    payload
  }
  if (encoded) {
    result.encoded = {
      header: encodedHeader,
      payload: encodedPayload
    }
  }
  return result
}
const decodeUnsecured = (token, encoded) => {
  validateToken(token)
  return _decodeUnsecured(token, encoded)
}

const _decode = (token, encoded) => {
  const {
    header,
    payload,
    encoded: {
      header: encodedHeader,
      payload: encodedPayload
    }
  } = _decodeUnsecured(token, true)
  const {
    alg: algorithm
  } = header
  let encodedSignature = null
  let signature = null
  if (algorithm !== NONE) {
    encodedSignature = StringPrototypeSlice(token, encodedHeader.length + encodedPayload.length + 2)
    if (!encodedSignature) {
      throw new JWTError(ERR_SIGNATURE_REQUIRED, 'The signature required')
    }
    signature = _decodeSignature(encodedSignature)
  }
  const result = {
    header,
    payload,
    signature
  }
  if (encoded) {
    result.encoded = {
      header: encodedHeader,
      payload: encodedPayload,
      signature: encodedSignature
    }
  }
  return result
}
const decode = (token, encoded) => {
  validateToken(token)
  return _decode(token, encoded)
}

const sign = (header, payload, key) => {
  validateHeader(header)
  validatePayload(payload)
  const {
    alg: algorithm
  } = header
  const encodedUnsecured = _encodeUnsecured(header, payload)
  let result = `${encodedUnsecured}${DELIMITER_CHAR}`
  if (algorithm !== NONE) {
    const signature = _createSignature(algorithm, encodedUnsecured, key)
    result += _encodeSignature(signature)
  }
  return result
}

const verify = (token, key, options) => {
  if (options === undefined) {
    options = {}
  } else if (!TypesIsPlainObject(options)) {
    throw new TypeError('The options must be a plain object')
  }
  let {
    ignoreNotBeforeDate,
    ignoreExpirationDate,
    maxAge
  } = options
  if (maxAge !== undefined) {
    maxAge = toMaxAge(maxAge)
  }
  validateToken(token)
  const {
    header,
    payload,
    signature,
    encoded: {
      header: encodedHeader,
      payload: encodedPayload,
    }
  } = _decode(token, true)
  const {
    alg: algorithm
  } = header
  if (algorithm !== NONE) {
    const encodedUnsecured = `${encodedHeader}${DELIMITER_CHAR}${encodedPayload}`
    const verified = _verifySignature(algorithm, encodedUnsecured, key, signature)
    if (!verified) {
      throw new JWTError(ERR_INVALID_SIGNATURE, 'Invalid signature')
    }
  }
  const {
    exp: expirationDate,
    nbf: notBeforeDate,
    iat: issuedAt
  } = payload
  const canProcessNotBeforeDate = notBeforeDate !== undefined && !ignoreNotBeforeDate
  const canProcessExpiration = expirationDate !== undefined && !ignoreExpirationDate
  const canProcessMaxAge = maxAge !== undefined && issuedAt !== undefined
  if (canProcessNotBeforeDate || canProcessExpiration || canProcessMaxAge) {
    const timestamp = getUnixTimestamp()
    if (canProcessNotBeforeDate && timestamp < notBeforeDate) {
      throw new JWTError(ERR_TOKEN_NOT_ACTIVE, 'Token is not active')
    }
    if (canProcessExpiration && timestamp >= expirationDate) {
      throw new JWTError(ERR_TOKEN_EXPIRED, 'Token expired')
    }
    if (canProcessMaxAge && timestamp >= issuedAt + maxAge) {
      throw new JWTError(ERR_TOKEN_EXPIRED, 'The maximum age of the token has expired')
    }
  }
  if (maxAge !== undefined && issuedAt === undefined) {
    throw new JWTError(ERR_TOKEN_EXPIRED, 'The maximum age of the token has expired')
  }
  return payload
}

class JWT {
  constructor(...args) {
    const [token] = args
    if (args.length === 1 && PrimitivesIsString(token)) {
      const {
        header,
        payload,
        signature,
        encoded: {
          header: encodedHeader,
          payload: encodedPayload,
          signature: encodedSignature
        }
      } = decode(token, true)
      this[headerSymbol] = header
      this[payloadSymbol] = payload
      this[signatureSymbol] = signature
      this[encodedHeaderSymbol] = encodedHeader
      this[encodedPayloadSymbol] = encodedPayload
      this[encodedSignatureSymbol] = encodedSignature
    } else {
      let [claims, options] = args
      if (options === undefined) {
        options = {}
      } else if (!TypesIsPlainObject(options)) {
        throw new TypeError('The options must be a plain object')
      }
      let {
        type,
        algorithm,
        issuer,
        subject,
        audience,
        expirationDate,
        notBeforeDate,
        issuedAt,
        jwtId,
        noTimestamp,
        expiresIn,
        notBefore
      } = options
      if (type === undefined) {
        type = TOKEN_TYPE
      } else if (type !== null) {
        validateTokenType(type)
      }
      algorithm = toAlgorithm(algorithm)
      if (issuer !== undefined) {
        issuer = String(issuer)
      }
      if (subject !== undefined) {
        subject = String(subject)
      }
      if (audience !== undefined) {
        audience = ArrayIsArray(audience) ? ArrayPrototypeMap(audience, String) : String(audience)
      }
      if (expirationDate !== undefined) {
        expirationDate = toUnixTimestamp(expirationDate)
      }
      if (notBeforeDate !== undefined) {
        notBeforeDate = toUnixTimestamp(notBeforeDate)
      }
      if (issuedAt !== undefined) {
        issuedAt = toUnixTimestamp(issuedAt)
      }
      if (jwtId !== undefined) {
        jwtId = String(jwtId)
      }
      if (expiresIn !== undefined) {
        expiresIn = TypesToIntegerOrInfinity(expiresIn)
        if (expiresIn < 0) {
          throw new RangeError('The expiresIn must be greater than or equal to zero')
        }
        if (expiresIn > NumberMAX_SAFE_INTEGER) {
          throw new RangeError('The expiresIn must be less than or equal to the maximum safe integer')
        }
      }
      if (notBefore !== undefined) {
        notBefore = TypesToIntegerOrInfinity(notBefore)
        if (notBefore < 0) {
          throw new RangeError('The notBefore must be greater than or equal to zero')
        }
        if (notBefore > NumberMAX_SAFE_INTEGER) {
          throw new RangeError('The notBefore must be less than or equal to the maximum safe integer')
        }
      }
      if (claims === undefined) {
        claims = {}
      } else {
        if (!TypesIsPlainObject(claims)) {
          throw new TypeError('The claims must be a plain object')
        }
        validatePayload(claims)
      }
      const {
        iss,
        sub,
        aud,
        exp,
        nbf,
        iat,
        jti
      } = claims
      const timestamp = (
        issuedAt !== undefined ? issuedAt :
        !noTimestamp ? getUnixTimestamp() :
        iat !== undefined ? iat : null
      )
      const header = ObjectCreate(null)
      if (type !== null) {
        header.typ = type
      }
      header.alg = algorithm
      const payload = ObjectCreate(null)
      if (issuer !== undefined) {
        payload.iss = issuer
      } else if (iss !== undefined) {
        payload.iss = iss
      }
      if (subject !== undefined) {
        payload.sub = subject
      } else if (sub !== undefined) {
        payload.sub = sub
      }
      if (audience !== undefined) {
        payload.aud = audience
      } else if (aud !== undefined) {
        payload.aud = aud
      }
      let time = timestamp
      if (expirationDate !== undefined) {
        payload.exp = expirationDate
      } else if (expiresIn !== undefined) {
        if (time === null) {
          time = getUnixTimestamp()
        }
        payload.exp = time + expiresIn
      } else if (exp !== undefined) {
        payload.exp = exp
      }
      if (notBeforeDate !== undefined) {
        payload.nbf = notBeforeDate
      } else if (notBefore !== undefined) {
        if (time === null) {
          time = getUnixTimestamp()
        }
        payload.nbf = time + notBefore
      } else if (nbf !== undefined) {
        payload.nbf = nbf
      }
      if (timestamp !== null) {
        payload.iat = timestamp
      }
      if (jwtId !== undefined) {
        payload.jti = jwtId
      } else if (jti !== undefined) {
        payload.jti = jti
      }
      ArrayPrototypeForEach(ObjectEntries(claims), ([key, value]) => {
        if (payload[key] === undefined) {
          payload[key] = value
        }
      })
      this[headerSymbol] = header
      this[payloadSymbol] = payload
      this[signatureSymbol] = null
      this[encodedHeaderSymbol] = null
      this[encodedPayloadSymbol] = null
      this[encodedSignatureSymbol] = null
    }
  }

  get header() {
    return this[headerSymbol]
  }

  set header(value) {
    if (value === undefined) {
      const header = {
        typ: TOKEN_TYPE,
        alg: ALGORITHM
      }
      ReflectSetPrototypeOf(header, null)
      this[headerSymbol] = header
    } else {
      validateHeader(value)
      this[headerSymbol] = value
    }
  }

  get type() {
    return this[headerSymbol].typ
  }

  set type(value) {
    if (value !== undefined) {
      validateTokenType(value)
    }
    this[headerSymbol].typ = value
  }

  get algorithm() {
    return this[headerSymbol].alg
  }

  set algorithm(value) {
    this[headerSymbol].alg = toAlgorithm(value)
  }

  get payload() {
    return this[payloadSymbol]
  }

  set payload(value) {
    if (value === undefined) {
      this[payloadSymbol] = ObjectCreate(null)
    } else {
      validatePayload(value)
      this[payloadSymbol] = value
    }
  }

  get issuer() {
    return this[payloadSymbol].iss
  }

  set issuer(value) {
    this[payloadSymbol].iss = value !== undefined ? String(value) : value
  }

  get subject() {
    return this[payloadSymbol].sub
  }

  set subject(value) {
    this[payloadSymbol].sub = value !== undefined ? String(value) : value
  }

  get audience() {
    return this[payloadSymbol].aud
  }

  set audience(value) {
    this[payloadSymbol].aud = value !== undefined ? (
      ArrayIsArray(value) ? ArrayPrototypeMap(value, String) : String(value)
    ) : value
  }

  get expirationDate() {
    return this[payloadSymbol].exp
  }

  set expirationDate(value) {
    this[payloadSymbol].exp = value !== undefined ? toUnixTimestamp(value) : value
  }

  get notBeforeDate() {
    return this[payloadSymbol].nbf
  }

  set notBeforeDate(value) {
    this[payloadSymbol].nbf = value !== undefined ? toUnixTimestamp(value) : value
  }

  get issuedAt() {
    return this[payloadSymbol].iat
  }

  set issuedAt(value) {
    this[payloadSymbol].iat = value !== undefined ? toUnixTimestamp(value) : value
  }

  get jwtId() {
    return this[payloadSymbol].jti
  }

  set jwtId(value) {
    this[payloadSymbol].jti = value !== undefined ? String(value) : undefined
  }

  get signature() {
    return this[signatureSymbol]
  }

  set signature(value) {
    if (value == null) {
      this[signatureSymbol] = null
    } else {
      validateSignature(value)
      this[signatureSymbol] = value
    }
  }

  get encodedHeader() {
    return this[encodedHeaderSymbol]
  }

  get encodedPayload() {
    return this[encodedPayloadSymbol]
  }

  get encodedSignature() {
    return this[encodedSignatureSymbol]
  }

  get ttl() {
    const {
      exp: expirationDate
    } = this[payloadSymbol]
    if (expirationDate === undefined) {
      return -1
    }
    const time = expirationDate - getUnixTimestamp()
    return time > 0 ? time : 0
  }

  get isActive() {
    const {
      nbf: notBeforeDate
    } = this[payloadSymbol]
    return notBeforeDate === undefined || getUnixTimestamp() >= notBeforeDate
  }

  get isExpired() {
    const {
      exp: expirationDate
    } = this[payloadSymbol]
    return expirationDate !== undefined && getUnixTimestamp() >= expirationDate
  }

  [encodeHeaderSymbol]() {
    return encodeHeader(this[headerSymbol])
  }

  encodeHeader() {
    return this[encodeHeaderSymbol]()
  }

  [encodePayloadSymbol]() {
    return encodePayload(this[payloadSymbol])
  }

  encodePayload() {
    return this[encodePayloadSymbol]()
  }

  [encodeSignatureSymbol]() {
    return encodeSignature(this[signatureSymbol])
  }

  encodeSignature() {
    return this[encodeSignatureSymbol]()
  }

  [encodeUnsecuredSymbol]() {
    return encodeUnsecured(this[headerSymbol], this[payloadSymbol])
  }

  encodeUnsecured() {
    return this[encodeUnsecuredSymbol]()
  }

  [encodeSymbol]() {
    return encode(this[headerSymbol], this[payloadSymbol], this[signatureSymbol])
  }

  encode() {
    return this[encodeSymbol]()
  }

  [createSignatureSymbol](key) {
    const {
      alg: algorithm
    } = this[headerSymbol]
    const encodedUnsecured = this[encodeUnsecuredSymbol]()
    return createSignature(algorithm, encodedUnsecured, key)
  }

  createSignature(key) {
    return this[createSignatureSymbol](key)
  }

  [verifySignatureSymbol](key) {
    const {
      alg: algorithm
    } = this[headerSymbol]
    const encodedUnsecured = `${this[encodedHeaderSymbol]}${DELIMITER_CHAR}${this[encodedPayloadSymbol]}`
    return verifySignature(algorithm, encodedUnsecured, key, this[signatureSymbol])
  }

  verifySignature(key) {
    return this[verifySignatureSymbol](key)
  }

  sign(key) {
    const {
      alg: algorithm
    } = this[headerSymbol]
    const encodedHeader = this[encodeHeaderSymbol]()
    const encodedPayload = this[encodePayloadSymbol]()
    const encodedUnsecured = `${encodedHeader}${DELIMITER_CHAR}${encodedPayload}`
    let result = `${encodedUnsecured}${DELIMITER_CHAR}`
    let signature = null
    let encodedSignature = null
    if (algorithm !== NONE) {
      signature = _createSignature(algorithm, encodedUnsecured, key)
      encodedSignature = _encodeSignature(signature)
      result += encodedSignature
    }
    this[signatureSymbol] = signature
    this[encodedHeaderSymbol] = encodedHeader
    this[encodedPayloadSymbol] = encodedPayload
    this[encodedSignatureSymbol] = encodedSignature
    return result
  }

  verify(key, options) {
    if (options === undefined) {
      options = {}
    } else if (!TypesIsPlainObject(options)) {
      throw new TypeError('The options must be a plain object')
    }
    let {
      ignoreNotBeforeDate,
      ignoreExpirationDate,
      maxAge
    } = options
    if (maxAge !== undefined) {
      maxAge = toMaxAge(maxAge)
    }
    const {
      alg: algorithm
    } = this[headerSymbol]
    if (algorithm !== NONE) {
      const verified = this[verifySignatureSymbol](key)
      if (!verified) {
        throw new JWTError(ERR_INVALID_SIGNATURE, 'Invalid signature')
      }
    }
    const payload = this[payloadSymbol]
    const {
      exp: expirationDate,
      nbf: notBeforeDate,
      iat: issuedAt
    } = payload
    const canProcessNotBeforeDate = notBeforeDate !== undefined && !ignoreNotBeforeDate
    const canProcessExpiration = expirationDate !== undefined && !ignoreExpirationDate
    const canProcessMaxAge = maxAge !== undefined && issuedAt !== undefined
    if (canProcessNotBeforeDate || canProcessExpiration || canProcessMaxAge) {
      const timestamp = getUnixTimestamp()
      if (canProcessNotBeforeDate && timestamp < notBeforeDate) {
        throw new JWTError(ERR_TOKEN_NOT_ACTIVE, 'Token is not active')
      }
      if (canProcessExpiration && timestamp >= expirationDate) {
        throw new JWTError(ERR_TOKEN_EXPIRED, 'Token expired')
      }
      if (canProcessMaxAge && timestamp >= issuedAt + maxAge) {
        throw new JWTError(ERR_TOKEN_EXPIRED, 'The maximum age of the token has expired')
      }
    }
    if (maxAge !== undefined && issuedAt === undefined) {
      throw new JWTError(ERR_TOKEN_EXPIRED, 'The maximum age of the token has expired')
    }
    return payload
  }
}

const isJWT = FunctionPrototypeBind(FunctionPrototypeSymbolHasInstance, null, JWT)

ObjectDefineProperties(JWT, {
  TOKEN_TYPE: {
    value: TOKEN_TYPE
  },
  ALGORITHM: {
    value: ALGORITHM
  },
  NONE: {
    value: NONE
  },
  DELIMITER_CHAR: {
    value: DELIMITER_CHAR
  },
  ERR_INVALID_TOKEN: {
    value: ERR_INVALID_TOKEN
  },
  ERR_INVALID_HEADER: {
    value: ERR_INVALID_HEADER
  },
  ERR_INVALID_TOKEN_TYPE: {
    value: ERR_INVALID_TOKEN_TYPE
  },
  ERR_INVALID_ALGORITHM: {
    value: ERR_INVALID_ALGORITHM
  },
  ERR_INVALID_PAYLOAD: {
    value: ERR_INVALID_PAYLOAD
  },
  ERR_INVALID_ISSUER: {
    value: ERR_INVALID_ISSUER
  },
  ERR_INVALID_SUBJECT: {
    value: ERR_INVALID_SUBJECT
  },
  ERR_INVALID_AUDIENCE: {
    value: ERR_INVALID_AUDIENCE
  },
  ERR_INVALID_EXPIRATION_DATE: {
    value: ERR_INVALID_EXPIRATION_DATE
  },
  ERR_INVALID_NOT_BEFORE_DATE: {
    value: ERR_INVALID_NOT_BEFORE_DATE
  },
  ERR_INVALID_ISSUED_AT: {
    value: ERR_INVALID_ISSUED_AT
  },
  ERR_INVALID_JWT_ID: {
    value: ERR_INVALID_JWT_ID
  },
  ERR_SIGNATURE_REQUIRED: {
    value: ERR_SIGNATURE_REQUIRED
  },
  ERR_INVALID_SIGNATURE: {
    value: ERR_INVALID_SIGNATURE
  },
  ERR_TOKEN_NOT_ACTIVE: {
    value: ERR_TOKEN_NOT_ACTIVE
  },
  ERR_TOKEN_EXPIRED: {
    value: ERR_TOKEN_EXPIRED
  },
  Error: {
    value: JWTError
  },
  isJWT: {
    value: isJWT
  },
  isJWTError: {
    value: isJWTError
  },
  getAlgorithms: {
    value: getAlgorithms
  },
  isAlgorithm: {
    value: isAlgorithm
  },
  createSignature: {
    value: createSignature
  },
  verifySignature: {
    value: verifySignature
  },
  encodeHeader: {
    value: encodeHeader
  },
  encodePayload: {
    value: encodePayload
  },
  encodeSignature: {
    value: encodeSignature
  },
  encodeUnsecured: {
    value: encodeUnsecured
  },
  encode: {
    value: encode
  },
  decodeHeader: {
    value: decodeHeader
  },
  decodePayload: {
    value: decodePayload
  },
  decodeSignature: {
    value: decodeSignature
  },
  decodeUnsecured: {
    value: decodeUnsecured
  },
  decode: {
    value: decode
  },
  sign: {
    value: sign
  },
  verify: {
    value: verify
  }
})
ObjectDefineProperties(JWT.prototype, {
  [SymbolToStringTag]: {
    value: 'JWT'
  }
})

module.exports = JWT
