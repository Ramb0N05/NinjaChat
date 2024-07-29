import { Common } from './Common.class.js'
import { Security } from './Security.class.js'
const S = Security.Init(false)

/**
 * Message Class
 * @export
 * @class
 */
export class Message {
  static get MessageDataObject () { return MessageDataObject }
  static get MessageMETADataObject () { return MessageMETADataObject }
  static get MessageSenderDataObject () { return MessageSenderDataObject }
  static get EncryptedMessageDataObject () { return EncryptedMessageDataObject }

  /**
   * Encrypts the message
   * @param {Security.Key} rsaWrappingKey
   * @param {(Security.DataArrayBuffer|ArrayBuffer|string|)} message
   * @param {number} expire
   * @param {Object} certificateObject
   * @returns {Promise.<Message.EncryptedMessageDataObject|false|null>}
   * @memberof Message
   */
  static async encryptAsync (rsaWrappingKey, message, expire, certificateObject) {
    if (S instanceof Security) {
      const newkey = await S.createKeyAsync('aes')

      if (newkey instanceof Security.Key && newkey.isValid() && rsaWrappingKey instanceof Security.Key && rsaWrappingKey.isValid()) {
        const encryptedNewkey = await S.wrapAESKeyAsync(rsaWrappingKey, newkey)
        let encryptedJSON = null

        if (Common.isString(message) || (message instanceof Security.DataArrayBuffer && message.isValid()) || message instanceof ArrayBuffer) {
          encryptedJSON = await S.encryptStrAESAsync(
            newkey,
            new MessageDataObject(message, expire, certificateObject).toJSONString()
          )
        }

        if (this.encryptedJSON instanceof Security.AESEncryptedObject && encryptedJSON.isValid() && encryptedNewkey instanceof Security.DataArrayBuffer && encryptedNewkey.isValid()) {
          const cryptIv = await S.encryptRSAAsync(rsaWrappingKey, encryptedJSON.IV)
          if (cryptIv instanceof Security.DataArrayBuffer && cryptIv.isValid() && encryptedJSON.encrypted instanceof Security.DataArrayBuffer && encryptedJSON.encrypted.isValid()) {
            return new EncryptedMessageDataObject(encryptedJSON.encrypted, encryptedNewkey, cryptIv)
          } else return null
        } else return null
      } else return null
    } else return false
  }

  /**
   * Decrypts the message
   * @param {(Security.Key|CryptoKey)} rsaUnwrappingKey
   * @param {string} encryptedJSONString
   * @return {Promise.<Security.DataArrayBuffer|false|null>}
   * @memberof Message
   */
  static async decryptAsync (rsaUnwrappingKey, encryptedJSONString) {
    if (rsaUnwrappingKey instanceof window.CryptoKey) rsaUnwrappingKey = new Security.Key(rsaUnwrappingKey)
    if (S instanceof Security && rsaUnwrappingKey instanceof Security.Key && rsaUnwrappingKey.isValid()) {
      const obj = EncryptedMessageDataObject.import(encryptedJSONString)

      if (obj instanceof EncryptedMessageDataObject &&
        obj.encryptedMessage instanceof Security.DataArrayBuffer && obj.encryptedMessage.isValid() &&
        obj.encryptedMessageKey instanceof Security.DataArrayBuffer && obj.encryptedMessageKey.isValid() &&
        obj.encryptedMessageIv instanceof Security.DataArrayBuffer && obj.encryptedMessageIv.isValid()
      ) {
        const messageKey = await S.unwrapAESKeyAsync(rsaUnwrappingKey, obj.encryptedMessageKey)
        const messageIv = await S.decryptRSAAsync(rsaUnwrappingKey, obj.encryptedMessageIv)

        if (messageKey instanceof Security.Key && messageKey.isValid() && messageIv instanceof Security.DataArrayBuffer && messageIv.isValid()) {
          return await S.decryptAESAsync(new Security.AESKeyObject(messageIv, messageKey), obj.encryptedMessage)
        } else return null
      } else return null
    } else return false
  }
}

/**
 * MessageMETADataObject Class
 * @class
 * @memberof Message
 */
class MessageMETADataObject {
  constructor (sender, expire) {
    const currentUnixTimeSeconds = Common.getCurrentUnixTime()
    this.Sender = sender
    this.Timestamp = currentUnixTimeSeconds
    this.Expire = (expire > 0 ? currentUnixTimeSeconds + expire : null)
  }

  /**
   * Sender Property
   * @readonly
   * @type {MessageSenderDataObject}
   * @memberof MessageMETADataObject
   */
  get Sender () { return this.Sender }
  /**
   * Timestamp Property
   * @readonly
   * @type {number}
   * @memberof MessageMETADataObject
   */
  get Timestamp () { return this.Timestamp }
  /**
   * Expire Property
   * @readonly
   * @type {number}
   * @memberof MessageMETADataObject
   */
  get Expire () { return this.Expire }

  toJSONObject () {
    return {
      Sender: (this.Sender instanceof MessageSenderDataObject ? this.Sender.toJSONObject() : undefined),
      Timestamp: this.Timestamp,
      Expire: this.Expire
    }
  }

  toJSONString () {
    return JSON.stringify(this.toJSONObject())
  }
}

/**
 * MessageSenderDataObject Class
 * @class
 * @memberof Message
 */
class MessageSenderDataObject {
  constructor (certificateObject) {
    this.UserName = certificateObject.name
    this.Tag = certificateObject.tag
    this.Serial = certificateObject.serial
  }

  get UserName () { return this.UserName }
  get Tag () { return this.Tag }
  get Serial () { return this.Serial }

  toJSONObject () {
    return {
      UserName: this.UserName,
      Tag: this.Tag,
      Expire: this.Expire
    }
  }

  toJSONString () {
    return JSON.stringify(this.toJSONObject())
  }
}

/**
 * MessageDataObject Class
 * @class
 * @memberof Message
 */
class MessageDataObject {
  /**
   * Creates an instance of MessageDataObject
   * @param {(Security.DataArrayBuffer|ArrayBuffer|string)} message
   * @param {number} expire
   * @param {Object} certificateObject
   * @memberof MessageDataObject
   */
  constructor (message, expire, certificateObject) {
    if (!isNaN(expire) && certificateObject instanceof Object) {
      this.META = new MessageMETADataObject(
        new MessageSenderDataObject(certificateObject),
        expire
      )

      if (message instanceof ArrayBuffer) message = new Security.DataArrayBuffer(message)
      if (message instanceof Security.DataArrayBuffer && message.isValid()) {
        this.payload = message.ValueBase64
      } else if (Common.isString(message)) {
        this.payload = window.btoa(message)
      } else this.payload = null
    } else {
      this.META = null
      this.payload = null
    }
  }

  /**
   * META Property
   * @readonly
   * @type {MessageMETADataObject}
   * @memberof MessageDataObject
   */
  get META () { return this.META }
  /**
   * Payload Property
   * @readonly
   * @type {string}
   * @memberof MessageDataObject
   */
  get payload () { return this.payload }

  /**
   * Convert instance to a JSON object
   * @returns {Object}
   * @memberof MessageDataObject
   */
  toJSONObject () {
    return {
      META: (this.META instanceof MessageMETADataObject ? this.META.toJSONObject() : undefined),
      payload: this.payload
    }
  }

  /**
   * Convert instance to a JSON string (Synonym: "json.")
   * @alias JSON.stringify(MessageDataObject.toJSONObject())
   * @returns {string}
   * @memberof MessageDataObject
   */
  toJSONString () {
    return JSON.stringify(this.toJSONObject())
  }
}

/**
 * EncryptedMessageDataObject Class
 * @class
 * @memberof Message
 */
class EncryptedMessageDataObject {
  /**
   * Creates an instance of EncryptedMessageDataObject
   * @param {(Security.DataArrayBuffer|ArrayBuffer)} encryptedMessage
   * @param {(Security.DataArrayBuffer|ArrayBuffer)} encryptedMessageKey
   * @param {(Security.DataArrayBuffer|Uint8Array)} encryptedMessageIv
   * @memberof EncryptedMessageDataObject
   */
  constructor (encryptedMessage, encryptedMessageKey, encryptedMessageIv) {
    this.encryptedMessage = (encryptedMessage instanceof Security.DataArrayBuffer && encryptedMessage.isValid() ? encryptedMessage : (encryptedMessage instanceof ArrayBuffer ? new Security.DataArrayBuffer(encryptedMessage) : null))
    this.encryptedMessageKey = (encryptedMessageKey instanceof Security.DataArrayBuffer && encryptedMessageKey.isValid() ? encryptedMessageKey : (encryptedMessageKey instanceof ArrayBuffer ? new Security.DataArrayBuffer(encryptedMessageKey) : null))
    this.encryptedMessageIv = (encryptedMessageIv instanceof Security.DataArrayBuffer && encryptedMessageIv.isValid() ? encryptedMessageIv : (encryptedMessageIv instanceof Uint8Array ? new Security.DataArrayBuffer(encryptedMessageIv) : null))
  }

  /**
   * Create new instance from Base64 encoded JSON string
   * @static
   * @param {string} encryptedJSONString
   * @returns {(EncryptedMessageDataObject|false)}
   * @memberof EncryptedMessageDataObject
   */
  static import (encryptedJSONString) {
    if (Common.isBase64(encryptedJSONString)) {
      const encryptedJSONObject = JSON.parse(window.atob(encryptedJSONString))

      if (Common.isset(() => encryptedJSONObject.enc_key) && Common.isset(() => encryptedJSONObject.enc_message) && Common.isset(() => encryptedJSONObject.enc_message.iv) && Common.isset(() => encryptedJSONObject.enc_message.data)) {
        return new EncryptedMessageDataObject(
          Common.b642ab(encryptedJSONObject.enc_message.data),
          Common.b642ab(encryptedJSONObject.enc_key),
          Common.b642ab(encryptedJSONObject.enc_message.iv)
        )
      } else return false
    } else return false
  }

  /**
   * EncryptedMessage Property
   * @readonly
   * @type {Security.DataArrayBuffer}
   */
  get EncryptedMessage () { return this.encryptedMessage }
  /**
   * EncryptedMessageKey Property
   * @readonly
   * @type {Security.DataArrayBuffer}
   */
  get EncryptedMessageKey () { return this.encryptedMessageKey }
  /**
   * EncryptedMessageIv Property
   * @readonly
   * @type {Security.DataArrayBuffer}
   */
  get EncryptedMessageIv () { return this.encryptedMessageIv }

  /**
   * Convert instance to JSON Object
   * @returns {Object}
   * @memberof EncryptedMessageDataObject
   */
  toJSONObject () {
    if (this.encryptedMessage instanceof Security.DataArrayBuffer && this.encryptedMessageKey instanceof Security.DataArrayBuffer && this.encryptedMessageIv instanceof Security.DataArrayBuffer) {
      return {
        enc_key: this.encryptedMessageKey.ValueBase64,
        enc_message: {
          iv: this.encryptedMessageIv.ValueBase64,
          data: this.encryptedMessage.ValueBase64
        }
      }
    }
  }

  /**
   * Convert instance to JSON string
   * @returns {string}
   * @memberof EncryptedMessageDataObject
   */
  toJSONString () {
    return JSON.stringify(this.toJSONObject())
  }

  /**
   * Export instance as Base64 encoded JSON string
   * @returns {string}
   * @memberof EncryptedMessageDataObject
   */
  export () {
    return window.btoa(this.toJSONString())
  }
}
