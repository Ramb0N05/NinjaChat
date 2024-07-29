import { Common } from './Common.class.js'
import { Message } from './Message.class.js'
import { Security } from './Security.class.js'
import 'https://cdn.neuland.ninja/jquery/3-7-1/jquery-3.7.1.min.js'
import 'https://cdn.neuland.ninja/materializecss/2-0-3_alpha/js/materialize.es6.js'
import 'https://cdn.neuland.ninja/hash-wasm/4-9-0/index.umd.min.js'
import { IDBStorage } from './IDBStorage.class.js'
const $ = window.jQuery = jQuery
const M = window.M
const S = Security.Init(false)
const HW = window.hashwasm

/**
 * NewAdvertise Callback
 * @typedef {function(NewAdvertiseResponse)}
 * @callback Session.NewAdvertiseCallback
 * @param {NewAdvertiseResponse} responseData
 */
/**
 * @typedef {Object} NewAdvertiseResponse
 * @property {boolean} result
 * @property {*} error
 */

/**
 * Advertise Callback
 * @typedef {function(AdvertiseResponse)}
 * @callback Session.AdvertiseCallback
 * @param {AdvertiseResponse} responseData
 */
/**
 * @typedef {Object} AdvertiseResponse
 * @property {(Array.<*>|false)} messages
 * @property {*} error
 */

/**
 * Session Callback
 * @typedef {function(SessionResponse)}
 * @callback Session.SessionCallback
 * @param {SessionResponse} responseData
 */
/**
 * @typedef {Object} SessionResponse
 * @property {Security.Key} pubkey
 * @property {*} adv_message
 */

/**
 * Session Class
 * @export
 * @class
 */
export class Session {
  /**
   * Creates an instance of Session
   * @param {string} sessionIdentifier
   * @param {(Security.Key|CryptoKey)} [sessionPublicKey=null]
   * @param {number} [sessionExpire=0]
   */
  constructor (sessionIdentifier, sessionPublicKey = null, sessionExpire = 0) {
    this.identifier = (Common.isString(sessionIdentifier) && !Common.isEmpty(sessionIdentifier) ? sessionIdentifier : null)
    this.publicKey = (sessionPublicKey instanceof Security.Key ? sessionPublicKey : (sessionPublicKey instanceof window.CryptoKey ? new Security.Key(sessionPublicKey) : null))
    this.expire = (!isNaN(sessionExpire) ? sessionExpire : 0)
  }

  /**
   * Identifier Length Constant property
   * @static
   * @constant
   * @readonly
   * @type {number}
   * @memberof Session
   */
  static get IDENTIFIER_LENGTH () { return 32 }

  /**
   * Generates a random session identifier
   * @static
   * @async
   * @param {number} [ivLength=16] The length of the initialization vector
   * @returns {Promise.<string>} A 32-digit session identifier
   * @memberof Session
   */
  static async generateIdentifierAsync (ivLength = 16) {
    return await HW.md5(
      Array.from(window.crypto.getRandomValues(new Uint8Array((ivLength >= 8 ? ivLength : 16))), function (dec) {
        return dec.toString(16).padStart(2, '0')
      }).join('')
    )
  }

  /**
   * Validate a given session identifier string
   * @static
   * @param {string} sessionIdentifier The session identifier to check
   * @param {(Element|$|string)} [submitButtonElement=null] A submit button element to enable or disable. Given as Element-Object, jQuery-Object or QuerySelector string.
   * @returns {boolean}
   * @memberof Session
   */
  static validateIdentifier (sessionIdentifier, submitButtonElement = null) {
    if (Common.isString(submitButtonElement)) submitButtonElement = window.document.querySelector(submitButtonElement)
    if (submitButtonElement instanceof $) submitButtonElement = submitButtonElement[0]

    if (submitButtonElement instanceof window.Element) {
      if (sessionIdentifier.length === Session.IDENTIFIER_LENGTH) {
        $(submitButtonElement).removeClass('disabled')
        return false
      } else {
        $(submitButtonElement).addClass('disabled')
        return true
      }
    } else return false
  }

  /**
   * Handler for the onclick event of a session link
   * @param {(Element|$|string)} linkEl
   * @param {(Element|$|string)} sessionPasswordModalEl
   * @param {IDBStorage} idb Instance of IDBStorage
   * @param {string} [type='active']
   */
  static linkHandler (linkEl, sessionPasswordModalEl, idb, type = 'active') {
    if (idb instanceof IDBStorage) {
      if (Common.isString(linkEl) && !Common.isEmpty(linkEl)) linkEl = window.document.querySelector(linkEl)
      if (linkEl instanceof $) linkEl = linkEl[0]

      if (Common.isString(sessionPasswordModalEl) && !Common.isEmpty(sessionPasswordModalEl)) sessionPasswordModalEl = window.document.querySelector(sessionPasswordModalEl)
      if (sessionPasswordModalEl instanceof $) sessionPasswordModalEl = sessionPasswordModalEl[0]

      if (linkEl instanceof window.Element && sessionPasswordModalEl instanceof window.Element) {
        const sessionO = new Session($(linkEl).text())
        const passwordEl = $(sessionPasswordModalEl).find('input[type="password"]')
        const sessionPasswordModal = M.Modal.getInstance(sessionPasswordModalEl)
        console.log(sessionO.identifier)

        if (sessionO instanceof Session) {
          idb.call('sessions', function (store) {
            const getData = store.get(sessionO.identifier)

            getData.onsuccess(async function () {
              switch (type) {
                case 'free':
                  sessionO.checkAdvertise(function (advMessage) {
                    if (Common.isset(() => advMessage, () => advMessage[0], () => advMessage[0].encrypted_key, () => advMessage[0].encrypted_message)) {
                      $(sessionPasswordModalEl).data('session-identifier', sessionO.identifier)

                      sessionPasswordModal.options.onCloseEnd = function () {
                        const priv = S.unwrapRSAKeyWithPassword(
                          new Security.DataArrayBuffer(getData.result.enc_privkey),
                          $(passwordEl).val(),
                          new Security.DataArrayBuffer(getData.result.sal),
                          new Security.DataArrayBuffer(getData.result.iv)
                        )

                        if (priv !== false && priv instanceof Security.Key) {
                          const msg = Message.decryptAsync(priv, advMessage[0])

                          if (msg instanceof Security.DataArrayBuffer) {
                            store.put({
                              id: getData.result.id,
                              iv: getData.result.iv,
                              sal: getData.result.sal,
                              pkey: getData.result.pkey,
                              enc_privkey: getData.result.enc_privkey,
                              foreign_pkey: msg.valueBase64
                            }, sessionO.identifier)
                          }
                        }
                      }

                      sessionPasswordModal.open()
                    }
                  })
                  break

                case 'active':
                default:
                  sessionO.retrieve(function (session) {

                  })
              }
            })
          })
        }
      }
    }
  }

  /**
   * The session identifier property
   * @readonly
   * @type {string}
   * @memberof Session
   */
  get Identifier () { return this.identifier }
  set Identifier (value) { return (Common.isString(value) && !Common.isEmpty(value) ? value : null) }

  /**
   * The public key of the session
   * @readonly
   * @type {(Security.Key|null)}
   * @memberof Session
   */
  get PublicKey () { return (this.publicKey instanceof Security.Key ? this.publicKey : null) }
  set PublicKey (value) { return (value instanceof Security.Key ? value : (value instanceof window.CryptoKey ? new Security.Key(value) : null)) }

  /**
   * The lifetime of the session in seconds
   * @readonly
   * @type {number}
   * @memberof Session
   */
  get Expire () { return this.expire }
  set Expire (value) { return (!isNaN(value) ? value : 0) }

  /**
   * Create a new session in database
   * @param {(Common.AjaxCallback|null)} [successCallback=null]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Session
   */
  create (successCallback = null, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    Common.ajaxPOST(
      Common.currentPath + 'backend/create.php?type=session',
      {
        session_identifier: this.identifier,
        session_public_key: JSON.stringify(this.publicKey),
        session_expire: this.expire
      },
      successCallback,
      errorCallback,
      logOnSuccessFallback,
      logOnErrorFallback
    )
  }

  /**
   * Creates a link list item for the session
   * @param {(Element|$|string)} linkContainerEl
   * @param {(Element|$|string)} sessionPasswordModalEl
   * @param {IDBStorage} idb Instance of IDBStorage
   * @param {string} [cssClass='']
   * @param {string} [handlerType='active']
   * @param {boolean} [cssWaves=true]
   * @param {string} [href='#']
   * @param {(string|null)} [content=null]
   * @returns {boolean}
   */
  createLinkListItem (linkContainerEl, sessionPasswordModalEl, idb, cssClass = '', handlerType = 'active', cssWaves = true, href = '#', content = null) {
    if (Common.isString(linkContainerEl)) linkContainerEl = window.document.querySelectorAll(linkContainerEl)
    if (linkContainerEl instanceof $) linkContainerEl = linkContainerEl[0]

    if (Common.isString(sessionPasswordModalEl)) sessionPasswordModalEl = window.document.querySelectorAll(sessionPasswordModalEl)
    if (sessionPasswordModalEl instanceof $) sessionPasswordModalEl = sessionPasswordModalEl[0]

    if (linkContainerEl instanceof window.Element && sessionPasswordModalEl instanceof window.Element && idb instanceof IDBStorage) {
      if (!Common.isString(cssClass)) cssClass = ''
      if (!Common.isString(href) || Common.isEmpty(href)) href = '#'
      if (!Common.isString(content) || Common.isEmpty(content)) content = this.identifier
      if (!Common.isString(content) || Common.isEmpty(content) || handlerType !== 'active' || handlerType !== 'free') handlerType = 'active'

      try {
        const classes = cssClass + (cssWaves ? ' waves-effect' : '')
        $(linkContainerEl).append('<li><a href="' + href + '" class="' + classes + '">' + (Common.isString(content) && !Common.isEmpty(content) ? content : this.identifier) + '</a></li>')
        $(linkContainerEl).find('li a').on('click', function () {
          Session.linkHandler($(this), sessionPasswordModalEl, idb, handlerType)
        })
        return true
      } catch {
        return false
      }
    } else return false
  }

  /**
   * Create a new advertise-message in database
   * @param {Message.EncryptedMessageDataObject} cryptmessage
   * @param {(Session.NewAdvertiseCallback|null)} [successCallback=null]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Session
   */
  createAdvertise (cryptmessage, successCallback = null, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    if (cryptmessage instanceof Message.EncryptedMessageDataObject) {
      Common.ajaxPOST(
        Common.currentPath + 'backend/create.php?type=advertise',
        {
          session_identifier: this.identifier,
          encrypted_message: cryptmessage.export()
        },
        successCallback,
        errorCallback,
        logOnSuccessFallback,
        logOnErrorFallback
      )
    } else Common.callCallback(errorCallback, { error: 'cryptmessage is not an instance of "Message.EncryptedMessageDataObject"' }, logOnErrorFallback)
  }

  /**
   * Check if an advertise-message is present in database
   * @param {(Session.AdvertiseCallback|null)} [successCallback=null]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Session
   */
  checkAdvertise (successCallback = null, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    Common.ajaxPOST(
      Common.currentPath + 'backend/get.php?realm=session&type=adv-message',
      { session_identifier: this.identifier },
      successCallback,
      errorCallback,
      logOnSuccessFallback,
      logOnErrorFallback
    )
  }

  /**
   * Retrieve session data from database
   * @param {(Session.SessionCallback|null)} [successCallback=null]
   * @param {boolean} [checkAdvertise=true]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Session
   */
  retrieve (successCallback = null, checkAdvertise = true, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    Common.ajaxPOST(
      Common.currentPath + 'backend/get.php?realm=current-user&type=session',
      { session_identifier: this.identifier },
      (data) => {
        if (Common.isset(() => data, () => data.session, () => data.session.identifier, () => data.session.pub_key) && data.session.identifier === this.identifier) {
          const cbResult = {
            pubkey: new Security.Key(data.session.pub_key),
            adv_message: false
          }

          if (checkAdvertise) { this.checkAdvertise((advertiseMessage) => { cbResult.adv_message = advertiseMessage }) }
          Common.callCallback(successCallback, cbResult, logOnSuccessFallback)
        } else Common.callCallback(errorCallback, (Common.isset(() => data.error) ? data.error : false))
      },
      errorCallback,
      logOnSuccessFallback,
      logOnErrorFallback
    )
  }
}
