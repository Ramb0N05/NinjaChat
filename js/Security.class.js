import { Common } from './Common.class.js'

/**
 * Security Class
 * @class
 */
export class Security {
  /**
   * Creates an instance of Security
   * @param {Crypto} crypto
   * @param {SubtleCrypto} subtle
   * @memberof Security
   */
  constructor (crypto, subtle) {
    this.cryptoInterface = (crypto instanceof window.Crypto ? crypto : null)
    this.subtleInterface = (subtle instanceof window.SubtleCrypto ? subtle : null)
  }

  static get Key () { return Key }
  static get KeyPair () { return KeyPair }
  static get KeyObject () { return KeyObject }
  static get AESKeyObject () { return AESKeyObject }
  static get DataArrayBuffer () { return DataArrayBuffer }
  static get PasswordKeyObject () { return PasswordKeyObject }
  static get AESEncryptedObject () { return AESEncryptedObject }

  /**
   * Initializes the WebCryptoAPI and returns an new instance of Security or FALSE if the WebCryptoAPI is not supported by the browser
   * @static
   * @param {boolean} [alertOnError=false] Displays an alert to the User if set to TRUE and the WebCryptoAPI is not supported by the browser
   * @returns {(Security|false)}
   * @memberof Security
   */
  static Initialize (alertOnError = false, logOnErrorFallback = true, errorMessage = 'Your browser does not support the Web Cryptography API! This page will not work.') {
    if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle) {
      window.crypto.subtle = window.crypto.webkitSubtle
    }
    if (!window.crypto || !window.crypto.subtle) {
      if (alertOnError === true) window.alert(errorMessage)
      else if (logOnErrorFallback === true) console.log(errorMessage)
      return false
    }

    return new Security(window.crypto, window.crypto.subtle)
  }

  /**
   * Initializes the WebCryptoAPI and returns a new instance of 'Security' or FALSE if the WebCryptoAPI is not supported by the browser
   * @static
   * @param {boolean} [alertOnError=false] Displays an alert to the User if set to TRUE and the WebCryptoAPI is not supported by the browser
   * @returns {(Security|false)}
   * @memberof Security
   */
  static Init (alertOnError = false, logOnErrorFallback = true) {
    return Security.Initialize(alertOnError, logOnErrorFallback)
  }

  /**
   * Instance of 'window.Crypto'
   * @readonly
   * @type {(Crypto|false)}
   * @memberof Security
   */
  get Crypto () {
    if (Common.isset(() => this.cryptoInterface) && this.cryptoInterface instanceof window.Crypto) return this.cryptoInterface
    else return false
  }

  /**
   * Instance of 'window.SubtleCrypto'
   * @readonly
   * @type {(SubtleCrypto|false)}
   * @memberof Security
   */
  get Subtle () {
    if (Common.isset(() => this.subtleInterface) && this.subtleInterface instanceof window.SubtleCrypto) return this.subtleInterface
    else return false
  }

  /**
   * Generates random values with the WebCryptoAPI
   * @param {number} length
   * @returns {(DataArrayBuffer|false)}
   * @memberof Security
   */
  generateRandomValues (length) {
    if (this.Crypto !== false) {
      if (isNaN(length) || length < 1) length = 1
      return new DataArrayBuffer(this.Crypto.getRandomValues(new Uint8Array(length)))
    } else return false
  }

  /**
   * Generates random values for a initializing vector with the WebCryptoAPI
   * @param {number} [length=12]
   * @returns {(DataArrayBuffer|false)}
   * @memberof Security
   */
  generateRandomIv (length = 12) {
    if (isNaN(length) || length < 1) length = 8
    return this.generateRandomValues(length)
  }

  /**
   * Generates random values for a salt with the WebCryptoAPI
   * @param {number} [length=16]
   * @returns {(DataArrayBuffer|false)}
   * @memberof Security
   */
  generateRandomSalt (length = 16) {
    if (isNaN(length) || length < 1) length = 8
    return this.generateRandomValues(length)
  }

  /**
   * Generates a new AES Key
   * @async
   * @param {string} [type='RSA']
   * @param {number} [length=0]
   * @returns {Promise.<Key|false>}
   * @memberof Security
   */
  async createKeyAsync (length = 0) {
    if (this.Subtle !== false) {
      if (isNaN(length)) length = 0

      return new Key(
        await this.Subtle.generateKey(
          {
            name: 'AES-GCM',
            length: (length >= 16 ? length : 256)
          },
          true,
          ['encrypt', 'decrypt']
        )
      )
    } else return false
  }

  /**
   * Generates a new RSA KeyPair
   * @async
   * @param {number} [length=0]
   * @return {Promise.<KeyPair|false>}
   * @memberof Security
   */
  async createKeyPairAsync (length = 0) {
    if (this.Subtle !== false) {
      if (isNaN(length)) length = 0

      const keypair = await this.Subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: (length >= 1024 ? length : 4096),
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: { name: 'SHA-256' }
        },
        true,
        ['encrypt', 'decrypt']
      )

      return new KeyPair(keypair.publicKey, keypair.privateKey)
    } else return false
  }

  /**
   * Generates a new AES-GCM key derived from a password string for wrapping and unwrapping keys
   * @async
   * @param {string} password
   * @param {(DataArrayBuffer|Uint8Array|null)} [salt=null] If NULL a new random salt will be generated
   * @returns {Promise.<PasswordKeyObject|false|null>}
   * @memberof Security
   */
  async createKeyFromPasswordAsync (password, salt = null) {
    if (this.Subtle !== false) {
      const enc = new TextEncoder()
      const tmpSalt = (
        salt instanceof DataArrayBuffer && salt.isValid()
          ? salt
          : (
              salt instanceof Uint8Array
                ? new DataArrayBuffer(salt)
                : this.generateRandomSalt()
            )
      )
      const keyPrototype = await this.Subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      )

      if (keyPrototype instanceof window.CryptoKey) {
        return new PasswordKeyObject(
          tmpSalt,
          await this.Subtle.deriveKey(
            {
              name: 'PBKDF2',
              salt: tmpSalt.value,
              iterations: 100000,
              hash: 'SHA-256'
            },
            keyPrototype,
            {
              name: 'AES-GCM',
              length: 256
            },
            true,
            ['wrapKey', 'unwrapKey']
          )
        )
      } else return null
    } else return false
  }

  /**
   * Encrypts data with an AES-GCM key
   * @async
   * @param {(Key|CryptoKey)} aesEncryptionKey AES-GCM Key
   * @param {(DataArrayBuffer|ArrayBuffer)} data
   * @returns {Promise.<AESEncryptedObject|false|null>}
   * @memberof Security
   */
  async encryptAESAsync (aesEncryptionKey, data) {
    if (this.Subtle) {
      if (aesEncryptionKey instanceof window.CryptoKey) aesEncryptionKey = new Key(aesEncryptionKey)
      if (data instanceof ArrayBuffer) data = new DataArrayBuffer(data)
      if (aesEncryptionKey instanceof Key && aesEncryptionKey.isValid() && data instanceof DataArrayBuffer && data.isValid()) {
        const tmpIv = this.generateRandomIv()

        if (tmpIv instanceof DataArrayBuffer && tmpIv.isValid()) {
          return new AESEncryptedObject(
            tmpIv,
            await this.Subtle.encrypt(
              {
                name: 'AES-GCM',
                iv: tmpIv.value
              },
              aesEncryptionKey.value,
              data.value
            )
          )
        } else return false
      } else return null
    } else return false
  }

  /**
   * Encrypts base64 encoded string with an AES-GCM key
   * @async
   * @param {(Key|CryptoKey)} aesEncryptionKey AES-GCM Key
   * @param {string} base64
   * @returns {Promise.<AESEncryptedObject|false|null>}
   * @memberof Security
   */
  async encryptBase64AESAsync (aesEncryptionKey, base64) {
    if (Common.isBase64(base64)) {
      return await this.encryptAESAsync(aesEncryptionKey, Common.b642ab(base64))
    } else return null
  }

  /**
   * Encodes string with base64 and encrypts with an AES-GCM key
   * @async
   * @param {(Key|CryptoKey)} aesEncryptionKey AES-GCM Key
   * @param {string} str
   * @returns {Promise.<AESEncryptedObject|false|null>}
   * @memberof Security
   */
  async encryptStrAESAsync (aesEncryptionKey, str) {
    if (Common.isString(str)) {
      return await this.encryptBase64AESAsync(aesEncryptionKey, window.btoa(str))
    } else return null
  }

  /**
   * Decrypts data with an AES-GCM key
   * @async
   * @param {AESKeyObject} aesDecryptionKey
   * @param {(DataArrayBuffer|ArrayBuffer)} data
   * @return {Promise.<DataArrayBuffer|false|null>}
   * @memberof Security
   */
  async decryptAESAsync (aesDecryptionKey, data) {
    if (this.Subtle !== false) {
      if (data instanceof ArrayBuffer) data = new DataArrayBuffer(data)
      if (data instanceof DataArrayBuffer && data.isValid() && aesDecryptionKey instanceof AESKeyObject && aesDecryptionKey.isValid()) {
        return new DataArrayBuffer(
          await this.Subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: aesDecryptionKey.IV.Value
            },
            aesDecryptionKey.Key.value,
            data.value
          )
        )
      } else return null
    } else return false
  }

  /**
   * Decrypts base64 encoded string with an AES-GCM key
   * @async
   * @param {AESKeyObject} aesDecryptionKey
   * @param {string} base64
   * @return {Promise.<DataArrayBuffer|false|null>}
   * @memberof Security
   */
  async decryptBase64AESAsync (aesDecryptionKey, base64) {
    if (Common.isBase64(base64)) {
      return new DataArrayBuffer(
        await this.decryptAESAsync(
          aesDecryptionKey,
          new DataArrayBuffer(Common.b642ab(base64))
        )
      )
    } else return null
  }

  /**
   * Encrypts data with an RSA-OAEP key
   * @async
   * @param {(Key|CryptoKey)} rsaWrappingKey RSA-OAEP key
   * @param {(DataArrayBuffer|ArrayBuffer)} data
   * @returns {Promise.<DataArrayBuffer|false|null>}
   * @memberof Security
   */
  async encryptRSAAsync (rsaWrappingKey, data) {
    if (this.Subtle !== false) {
      if (rsaWrappingKey instanceof window.CryptoKey) rsaWrappingKey = new Key(rsaWrappingKey)
      if (data instanceof ArrayBuffer) data = new DataArrayBuffer(data)
      if (rsaWrappingKey instanceof Key && rsaWrappingKey.isValid() && data instanceof DataArrayBuffer && data.isValid()) {
        return new DataArrayBuffer(
          await this.Subtle.encrypt({ name: 'RSA-OAEP' }, rsaWrappingKey.value, data.value)
        )
      } else return null
    } else return false
  }

  /**
   * Encrypts base64 encoded string with an RSA-OAEP key
   * @async
   * @param {(Key|CryptoKey)} rsaWrappingKey RSA-OAEP key
   * @param {string} base64
   * @returns {Promise.<DataArrayBuffer|false|null>}
   * @memberof Security
   */
  async encryptBase64RSAAsync (rsaWrappingKey, base64) {
    if (Common.isBase64(base64)) {
      return await this.encryptRSAAsync(rsaWrappingKey, new DataArrayBuffer(Common.b642ab(base64)))
    } else return false
  }

  /**
   * Encodes string with base64 and encrypts with an RSA-OAEP key
   * @async
   * @param {(Key|CryptoKey)} rsaWrappingKey RSA-OAEP key
   * @param {string} str
   * @returns {Promise.<DataArrayBuffer|false|null>}
   * @memberof Security
   */
  async encryptStrRSAAsync (rsaWrappingKey, str) {
    if (Common.isString(str)) {
      return await this.encryptBase64RSAAsync(rsaWrappingKey, Common.btoa(str))
    } else return false
  }

  /**
   * Decrypts data with an RSA-OAEP key
   * @async
   * @param {(Key|CryptoKey)} rsaDecryptionKey
   * @param {(DataArrayBuffer|ArrayBuffer)} data
   * @return {Promise.<DataArrayBuffer>}
   * @memberof Security
   */
  async decryptRSAAsync (rsaDecryptionKey, data) {
    if (this.Subtle !== false) {
      if (data instanceof ArrayBuffer) data = new DataArrayBuffer(data)
      if (rsaDecryptionKey instanceof window.CryptoKey) data = new Key(rsaDecryptionKey)
      if (rsaDecryptionKey instanceof Key && rsaDecryptionKey.isValid() && data instanceof DataArrayBuffer && data.isValid()) {
        return new DataArrayBuffer(
          this.Subtle.decrypt(
            {
              name: 'RSA-OAEP',
              hash: 'SHA-256'
            },
            rsaDecryptionKey.value,
            data.value
          )
        )
      } else return null
    } else return false
  }

  /**
   * Decrypts base64 encoded data with an RSA-OAEP key
   * @async
   * @param {(Key|CryptoKey)} rsaDecryptionKey
   * @param {string} base64
   * @return {Promise.<DataArrayBuffer>}
   * @memberof Security
   */
  async decryptBase64RSAAsync (rsaDecryptionKey, base64) {
    if (Common.isBase64(base64)) {
      await this.decryptRSAAsync(rsaDecryptionKey, Common.b642ab(base64))
    } else return false
  }

  /**
   * Wraps an AES-GCM key with a RSA-OAEP key
   * @async
   * @param {(Key|CryptoKey)} aesKey AES-GCM key
   * @param {(Key|CryptoKey)} rsaWrappingKey RSA-OAEP key
   * @returns {Promise.<DataArrayBuffer|false|null>}
   * @memberof Security
   */
  async wrapAESKeyAsync (rsaWrappingKey, aesKey) {
    if (this.Subtle !== null) {
      if (aesKey instanceof window.CryptoKey) aesKey = new Key(aesKey)
      if (rsaWrappingKey instanceof window.CryptoKey) rsaWrappingKey = new Key(rsaWrappingKey)
      if (aesKey instanceof Key && aesKey.isValid() && rsaWrappingKey instanceof Key && rsaWrappingKey.isValid()) {
        return new DataArrayBuffer(
          await this.Subtle.wrapKey(
            'jwk',
            aesKey.value,
            rsaWrappingKey.value,
            {
              name: 'RSA-OAEP',
              hash: 'SHA-256'
            }
          )
        )
      } else return null
    } else return false
  }

  /**
   * Wraps a RSA-OAEP key with an AES-GCM key
   * @async
   * @param {(Key|CryptoKey)} rsaKey RSA-OAEP key
   * @param {(AESKeyObject|PasswordKeyObject|Key|CryptoKey)} aesWrappingKey AES-GCM key
   * @returns {Promise.<AESEncryptedObject|false|null>}
   * @memberof Security
   */
  async wrapRSAKeyAsync (aesWrappingKey, rsaKey) {
    if (this.Subtle !== null) {
      let tmpIv = null

      if (rsaKey instanceof window.CryptoKey) rsaKey = new Key(rsaKey)
      if (aesWrappingKey instanceof window.CryptoKey) aesWrappingKey = new Key(aesWrappingKey)
      if (aesWrappingKey instanceof PasswordKeyObject && aesWrappingKey.isValid()) aesWrappingKey = aesWrappingKey.Key
      if (aesWrappingKey instanceof AESKeyObject && aesWrappingKey.isValid()) { tmpIv = aesWrappingKey.IV; aesWrappingKey = aesWrappingKey.Key }

      if (rsaKey instanceof Key && rsaKey.isValid() && aesWrappingKey instanceof Key && aesWrappingKey.isValid()) {
        if (!(tmpIv instanceof DataArrayBuffer) || !tmpIv.isValid) tmpIv = this.generateRandomIv()
        if (tmpIv instanceof DataArrayBuffer && tmpIv.isValid()) {
          return new AESEncryptedObject(
            tmpIv,
            await this.Subtle.wrapKey(
              'jwk',
              rsaKey.value,
              aesWrappingKey.value,
              {
                name: 'AES-GCM',
                iv: tmpIv.value
              }
            )
          )
        } else return false
      } else return null
    } else return false
  }

  /**
   * Wraps a RSA-OAEP key with an AES-GCM key generated by a password
   * @async
   * @param {(Key|CryptoKey)} rsaKey RSA-OAEP key
   * @param {string} password Password
   * @param {(DataArrayBuffer|Uint8Array|null)} [salt=null] The salt for the password. A random salt is generated if set to NULL or the salt is invalid
   * @returns {Promise.<AESEncryptedObject|false|null>}
   * @memberof Security
   */
  async wrapRSAKeyWithPasswordAsync (rsaKey, password, salt = null) {
    if (this.Subtle !== null) {
      if (salt instanceof Uint8Array) salt = new DataArrayBuffer(salt)
      salt = (salt instanceof DataArrayBuffer ? salt : this.generateRandomSalt())
      const aesWrappingKey = await this.createKeyFromPasswordAsync(password, salt)
      const wrappedKey = await this.wrapRSAKeyAsync(aesWrappingKey, rsaKey)

      if (wrappedKey instanceof AESEncryptedObject && wrappedKey.isValid()) {
        wrappedKey.Salt = salt
        return wrappedKey
      } else return null
    } else return false
  }

  /**
   * Unwraps an wrapped AES-GCM key with an RSA-OAEP key for decryption
   * @async
   * @param {(DataArrayBuffer|ArrayBuffer)} wrappedAesKey wrapped AES-GCM key
   * @param {(Key|CryptoKey)} rsaUnwrappingKey RSA-OAEP key
   * @returns {Promise.<Key|false|null>}
   * @memberof Security
   */
  async unwrapAESKeyAsync (rsaUnwrappingKey, wrappedAesKey) {
    if (this.Subtle !== false) {
      if (rsaUnwrappingKey instanceof window.CryptoKey) rsaUnwrappingKey = new Key(rsaUnwrappingKey)
      if (wrappedAesKey instanceof ArrayBuffer) wrappedAesKey = new DataArrayBuffer(wrappedAesKey)
      if (wrappedAesKey instanceof DataArrayBuffer && wrappedAesKey.isValid() && rsaUnwrappingKey instanceof Key && rsaUnwrappingKey.isValid()) {
        return new Key(
          await this.Subtle.unwrapKey(
            'jwk',
            wrappedAesKey.value,
            rsaUnwrappingKey.value,
            {
              name: 'RSA-OAEP',
              hash: 'SHA-256'
            },
            { name: 'AES-GCM' },
            true,
            ['decrypt']
          )
        )
      } else return null
    } else return false
  }

  /**
   * Unwraps a wrapped RSA-OAEP key with an AES-GCM key for decryption
   * @async
   * @param {(DataArrayBuffer|ArrayBuffer)} wrappedRsaKey wrapped RSA-OAEP key
   * @param {AESKeyObject} unwrappingAesKey
   * @returns {Promise.<Key|false|null>}
   * @memberof Security
   */
  async unwrapRSAKeyAsync (unwrappingAesKey, wrappedRsaKey) {
    if (this.Subtle !== false) {
      if (wrappedRsaKey instanceof ArrayBuffer) wrappedRsaKey = new DataArrayBuffer(wrappedRsaKey)
      if (
        wrappedRsaKey instanceof DataArrayBuffer &&
        wrappedRsaKey.isValid() &&
        unwrappingAesKey instanceof AESKeyObject &&
        unwrappingAesKey.isValid() &&
        unwrappingAesKey.IV instanceof DataArrayBuffer &&
        unwrappingAesKey.Key instanceof Key
      ) {
        return new Key(
          await this.Subtle.unwrapKey(
            'jwk',
            wrappedRsaKey.value,
            unwrappingAesKey.Key.value,
            {
              name: 'AES-GCM',
              iv: unwrappingAesKey.IV.Value
            },
            {
              name: 'RSA-OAEP',
              hash: 'SHA-256'
            },
            true,
            ['decrypt']
          )
        )
      } else return null
    } else return false
  }

  /**
   * Unwraps a wrapped RSA-OAEP key with an AES-GCM key derived from password, salt and iv for decryption
   * @async
   * @param {(DataArrayBuffer|ArrayBuffer)} wrappedRsaKey wrapped RSA-OAEP key
   * @param {string} password Password
   * @param {(DataArrayBuffer|Uint8Array)} salt
   * @param {(DataArrayBuffer|Uint8Array|null)} iv
   * @return {Promise.<Key|false|null>}
   * @memberof Security
   */
  async unwrapRSAKeyWithPasswordAsync (wrappedRsaKey, password, salt, iv) {
    const unwrappingKey = this.createKeyFromPasswordAsync(password, salt)

    if (!(iv instanceof DataArrayBuffer || iv instanceof Uint8Array || iv.length < 1)) iv = this.generateRandomIv()
    if (unwrappingKey instanceof PasswordKeyObject && unwrappingKey.Key instanceof Key) {
      return await this.unwrapRSAKeyAsync(new AESKeyObject(iv, unwrappingKey.Key.value), wrappedRsaKey)
    } else return null
  }

  /**
   * Export a given Key to a JsonWebKey
   * @async
   * @param {(Key|CryptoKey)} key
   * @param {boolean} [toJSONString=false] Stringifies the JsonWebKey Object if set to TRUE
   * @param {boolean} [encodeBase64=false] Encodes the stringified JsonWebKey Object with base64 if set to TRUE (only if 'toJSONString' is also set to TRUE)
   * @returns {Promise.<JsonWebKey|string|false>}
   * @memberof Security
   */
  async exportKeyAsync (key, toJSONString = false, encodeBase64 = false) {
    if (key instanceof window.CryptoKey) key = new Key(key)
    if (key instanceof Key && key.isValid()) {
      const jwk = await this.Subtle.exportKey('jwk', key.value)
      return (toJSONString === true ? (encodeBase64 === true ? window.btoa(JSON.stringify(jwk)) : JSON.stringify(jwk)) : jwk)
    } else return false
  }

  /**
   * Import a given JsonWebKey
   * @async
   * @param {(JsonWebKey|string)} jwk The JsonWebKey as object or json string (accepts also a base64 encoded string)
   * @param {(string|Algorithm|RsaHashedImportParams|EcKeyImportParams|HmacImportParams|DhImportKeyParams|AesKeyAlgorithm)} algorithm
   * @param {boolean} [extractable=true]
   * @param {Array.<string>} [keyUsage=['encrypt', 'decrypt']]
   * @returns {Promise.<Key|false|null>}
   * @memberof Security
   */
  async importKeyAsync (jwk, algorithm, extractable = true, keyUsage = ['encrypt', 'decrypt']) {
    if (Common.isString(jwk)) jwk = (Common.isBase64(jwk) ? JSON.parse(window.atob(jwk)) : JSON.parse(jwk))
    if (jwk instanceof Object) {
      const tmpKey = new Key(
        await this.Subtle.importKey(
          'jwk',
          jwk,
          algorithm,
          extractable,
          keyUsage
        )
      )

      if (tmpKey instanceof Key && tmpKey.isValid()) return tmpKey
      else return null
    } else return false
  }
}

/**
 * DataArrayBuffer Class
 * @class
 * @export
 * @memberof Security
 */
class DataArrayBuffer {
  /**
   * Creates an instance of DataArrayBuffer
   * @param {(ArrayBuffer|Uint8Array|string)} val Accepts ArrayBuffers or a Base64 string
   */
  constructor (val) {
    if (Common.isBase64(val)) val = Common.b642ab(val)
    this.value = (this.isValid(val) ? val : null)
  }

  /**
   * Value
   * @type {(ArrayBuffer|Uint8Array|null)}
   */
  get Value () {
    const val = this.value
    if (this.value instanceof Uint8Array) Object.assign(Uint8Array, val)
    else if (this.value instanceof ArrayBuffer) Object.assign(ArrayBuffer, val)
    return val
  }

  set Value (val) { this.value = (this.isValid(val) ? val : null) }

  /**
   * Base64 encoded value
   * @readonly
   * @type {(string|null)}
   */
  get ValueBase64 () {
    return (this.isValid() ? Common.ab2b64(this.value) : null)
  }

  /**
   * String of value
   * @readonly
   * @type {(string|null)}
   */
  get ValueToString () {
    return this.toString()
  }

  /**
   * Converts value to string
   * @param {('base64'|'b64'|1|'decode'|'dec'|2|null|*)} [method=1]
   * @return {(string|null)}
   */
  toString (method = null) {
    if (method === null || method === 1 || !Common.isString(method) || method === 'b64' || method === 'base64') {
      const a = this.ValueBase64
      return (this.isValid() && Common.isBase64(a) ? window.atob(a) : null)
    } else if (method === 2 || method === 'dec' || method === 'decode') {
      return (this.isValid() ? Common.ab2str(this.value) : null)
    } else return null
  }

  /**
   * Validate
   * @param {(ArrayBuffer|Uint8Array|null)} [val=null]
   * @return {boolean}
   */
  isValid (val = null) {
    if (val === null) return (this.value instanceof ArrayBuffer || this.value instanceof Uint8Array)
    else return (val instanceof ArrayBuffer || val instanceof Uint8Array)
  }
}

/**
 * Key Class
 * @class
 * @memberof Security
 */
class Key {
  /**
   * Creates an instance of Key
   * @param {CryptoKey} key
   */
  constructor (key) {
    this.value = (key instanceof window.CryptoKey ? key : null)
  }

  /**
   * Value
   * @type {(CryptoKey|null)}
   */
  get Value () { return this.value }
  set Value (val) { this.value = (this.isValid(val) ? val : null) }

  /**
   * JSON string of value
   * @readonly
   * @type {string}
   */
  get ValueJSON () {
    return (this.isValid() ? JSON.stringify(this.value) : null)
  }

  /**
   * Validate
   * @param {(CryptoKey|null)} [val=null]
   * @returns {boolean}
   */
  isValid (val = null) {
    if (val === null) return (this.value instanceof window.CryptoKey)
    else return (val instanceof window.CryptoKey)
  }
}

/**
 * KeyPair Class
 * @class
 * @memberof Security
 */
class KeyPair {
  /**
   * Creates an instance of Key
   * @param {CryptoKey} publicKey
   * @param {CryptoKey} privateKey
   */
  constructor (publicKey, privateKey) {
    this.publicKey = (publicKey instanceof window.CryptoKey ? publicKey : null)
    this.privateKey = (privateKey instanceof window.CryptoKey ? privateKey : null)
  }

  /**
   * Public Key Property
   * @type {(CryptoKey|null)}
   */
  get PublicKey () { return this.publicKey }
  set PublicKey (val) { this.publicKey = (this.isValid(val) ? val : null) }

  /**
   * Private Key Property
   * @type {(CryptoKey|null)}
   */
  get PrivateKey () { return this.privateKey }
  set PrivateKey (val) { this.privateKey = (this.isValid(val) ? val : null) }

  /**
   * JSON string of public Key
   * @readonly
   * @type {string}
   */
  get PublicKeyJSON () {
    return (this.isValid(this.publicKey) ? JSON.stringify(this.publicKey) : null)
  }

  /**
   * JSON string of private Key
   * @readonly
   * @type {string}
   */
  get PrivateKeyJSON () {
    return (this.isValid(this.privateKey) ? JSON.stringify(this.privateKey) : null)
  }

  /**
   * Validate
   * @param {(CryptoKey|null)} [val=null]
   * @returns {boolean}
   */
  isValid (val = null) {
    if (val === null) return (this.publicKey instanceof window.CryptoKey && this.privateKey instanceof window.CryptoKey)
    else return (val instanceof window.CryptoKey)
  }
}

/**
 * KeyObject Class
 * @class
 * @memberof Security
 */
class KeyObject {
  /**
   * Creates an instance of KeyObject
   * @param {(Key|CryptoKey)} key
   */
  constructor (key) {
    this.key = (this.isValid(key) ? key : (key instanceof window.CryptoKey ? new Key(key) : null))
  }

  /**
   * Key
   * @type {(Key|null)}
   */
  get Key () { return this.key }
  set Key (value) { this.key = (this.isValid(value) ? value : (value instanceof window.CryptoKey ? new Key(value) : null)) }

  /**
   * Validate
   * @param {(Key|null)} [val=null]
   * @return {boolean}
   */
  isValid (val = null) {
    if (val === null) return (this.key instanceof Key && this.key.isValid())
    else return (val instanceof Key && val.isValid())
  }
}

/**
 * AESKeyObject Class
 * @class
 * @extends KeyObject
 * @memberof Security
 */
class AESKeyObject extends KeyObject {
  /**
   * Creates an instance of AESKeyObject
   * @param {(DataArrayBuffer|Uint8Array)} iv
   * @param {(Key|CryptoKey))} key
   */
  constructor (iv, key) {
    super(key)
    this.iv = (iv instanceof DataArrayBuffer ? iv : (iv instanceof Uint8Array ? new DataArrayBuffer(iv) : null))
  }

  /**
   * Initializing vector
   * @type {(DataArrayBuffer|Uint8Array|null)}
   */
  get IV () { return this.iv }
  set IV (value) { this.iv = (value instanceof DataArrayBuffer ? value : (value instanceof Uint8Array ? new DataArrayBuffer(value) : null)) }

  /**
   * Validate
   * @param {(DataArrayBuffer|null)} [iv=null]
   * @param {(Key|null)} [key=null]
   * @return {boolean}
   */
  isValid (iv = null, key = null) {
    if (iv === null && key === null) return (this.iv instanceof DataArrayBuffer && this.iv.isValid() && this.Key instanceof Key && this.Key.isValid())
    else return (iv instanceof DataArrayBuffer && iv.isValid() && key instanceof Key && key.isValid())
  }
}

/**
 * AESEncryptedObject Class
 * @class
 * @memberof Security
 */
class AESEncryptedObject {
  /**
   * Creates an instance of AESEncryptedObject
   * @param {(DataArrayBuffer|Uint8Array)} iv
   * @param {(DataArrayBuffer|ArrayBuffer)} encrypted
   * @param {(DataArrayBuffer|Uint8Array)} salt
   */
  constructor (iv, encrypted, salt = null) {
    this.iv = (iv instanceof DataArrayBuffer ? iv : (iv instanceof Uint8Array ? new DataArrayBuffer(iv) : null))
    this.encrypted = (encrypted instanceof DataArrayBuffer ? encrypted : (encrypted instanceof ArrayBuffer ? new DataArrayBuffer(encrypted) : null))
    this.salt = (salt instanceof DataArrayBuffer ? salt : (salt instanceof Uint8Array ? new DataArrayBuffer(salt) : null))
  }

  /**
   * Initializing vector
   * @type {(DataArrayBuffer|null)}
   */
  get IV () { return this.iv }
  set IV (value) { this.iv = (value instanceof DataArrayBuffer ? value : (value instanceof Uint8Array ? new DataArrayBuffer(value) : null)) }

  /**
   * Encrypted data
   * @type {(DataArrayBuffer|null)}
   */
  get Encrypted () { return this.encrypted }
  set Encrypted (value) { this.encrypted = (value instanceof DataArrayBuffer ? value : (value instanceof ArrayBuffer ? new DataArrayBuffer(value) : null)) }

  /**
   * Salt for encryption key (only set if encrypted with password)
   * @type {(DataArrayBuffer|null)}
   */
  get Salt () { return this.salt }
  set Salt (value) { this.salt = (value instanceof DataArrayBuffer ? value : (value instanceof Uint8Array ? new DataArrayBuffer(value) : null)) }

  /**
   * Validate
   * @param {(DataArrayBuffer|null)} [iv=null]
   * @param {(DataArrayBuffer|null)} [encrypted=null]
   * @return {boolean}
   */
  isValid (iv = null, encrypted = null) {
    if (iv === null && encrypted === null) return (this.iv instanceof DataArrayBuffer && this.iv.isValid() && this.encrypted instanceof DataArrayBuffer)
    else return (iv instanceof DataArrayBuffer && iv.isValid() && encrypted instanceof DataArrayBuffer)
  }
}

/**
 * PasswordKeyObject Class
 * @class
 * @instance
 * @extends KeyObject
 * @memberof Security
 */
class PasswordKeyObject extends KeyObject {
  /**
   * Creates an instance of PasswordKeyObject
   * @param {(DataArrayBuffer|Uint8Array)} salt
   * @param {(Key|CryptoKey)} key
   */
  constructor (salt, key) {
    super(key)
    this.salt = (salt instanceof DataArrayBuffer && salt.isValid() ? salt : (salt instanceof Uint8Array ? new DataArrayBuffer(salt) : null))
  }

  /**
   * Password salt
   * @type {(DataArrayBuffer|null)}
   */
  get Salt () { return this.salt }
  set Salt (value) { this.salt = (value instanceof DataArrayBuffer ? value : null) }

  /**
   * Validate
   * @param {(DataArrayBuffer|null)} [salt=null]
   * @param {(CryptoKey|null)} [key=null]
   * @return {boolean}
   */
  isValid (salt = null, key = null) {
    if (salt === null && key === null) return (this.salt instanceof DataArrayBuffer && this.salt.isValid() && this.Key instanceof Key && this.Key.isValid())
    else return (salt instanceof DataArrayBuffer && salt.isValid() && key instanceof Key && key.isValid())
  }
}
