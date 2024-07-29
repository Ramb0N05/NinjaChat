import 'https://cdn.neuland.ninja/jquery/3-7-1/jquery-3.7.1.min.js'
const $ = window.jQuery = jQuery

export const MAXLENGTH_DEFAULT = 300
export const MAXLENGTH_MOBILE = 150
export const PASS_CHECK_LENGTH = 12
export const PASS_CHECK_FULL = /^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*?[!@#$%^&*=€])(?=.{' + PASS_CHECK_LENGTH + ',})/
export const PASS_CHECK = {
  Numeric: /^(?=.*[0-9])/,
  Alpha: /^(?=.*[A-Z])(?=.*[a-z])/,
  Special: /^(?=.*?[!@#$%^&*=€])/,
  Length: /^(?=.{' + PASS_CHECK_LENGTH + ',})/
}

export function isset (accessor) {
  try {
    return accessor() !== undefined && accessor() !== null
  } catch (e) {
    return false
  }
}

export async function sha256 (message) {
  // encode as UTF-8
  const msgBuffer = new TextEncoder().encode(message)

  // hash the message
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer)

  // convert ArrayBuffer to Array
  const hashArray = Array.from(new Uint8Array(hashBuffer))

  // convert bytes to hex string
  const hashHex = hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('')
  return hashHex
}

export function ab2str (buf) {
  const decoder = new TextDecoder()
  return decoder.decode(buf)
}

export function str2ab (str) {
  const encoder = new TextEncoder()
  return encoder.encode(str)
}

export function ab2b64 (buffer) {
  let binary = ''
  const bytes = new Uint8Array(buffer)
  const len = bytes.byteLength
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return window.btoa(binary)
}

export function b642ab (base64) {
  const binaryString = window.atob(base64)
  const len = binaryString.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }
  return bytes.buffer
}

export function getKeyProto (passwordStr) {
  const enc = new TextEncoder()
  return window.crypto.subtle.importKey(
    'raw',
    enc.encode(passwordStr),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  )
}

export function getKey (keyProto, salt) {
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyProto,
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['wrapKey', 'unwrapKey']
  )
}

export async function wrapKey (key, wrappingKey, keyType = 'rsa') {
  const keyProto = await getKeyProto(wrappingKey)
  const tmpSalt = generateRandomValues(16)
  const tmpIv = generateRandomValues(12)
  const wrappingKeyAES = await getKey(keyProto, tmpSalt)

  switch (keyType) {
    case 'aes':
    case 'AES':
      return window.crypto.subtle.wrapKey(
        'jwk',
        key,
        wrappingKey,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256'
        }
      )

    case 'rsa':
    case 'RSA':
    default:
      return {
        iv: tmpIv,
        salt: tmpSalt,
        wrapped_key: window.crypto.subtle.wrapKey(
          'jwk',
          key,
          wrappingKeyAES,
          {
            name: 'AES-GCM',
            iv: tmpIv
          }
        )
      }
  }
}

export function unwrapKey (wrappedKey, passwordStr, salt, iv) {
  return unwrapRSAKey(wrappedKey, passwordStr, salt, iv)
}

export async function unwrapRSAKey (wrappedKey, passwordStr, salt, iv) {
  const keyProto = await getKeyProto(passwordStr)
  const unwrappingKey = await getKey(keyProto, salt)

  return window.crypto.subtle.unwrapKey(
    'jwk',
    wrappedKey,
    unwrappingKey,
    {
      name: 'AES-GCM',
      iv: iv
    },
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['decrypt']
  )
}

export function unwrapAESKey (wrappedKey, unwrappingKey) {
  return window.crypto.subtle.unwrapKey(
    'jwk',
    wrappedKey,
    unwrappingKey,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    { name: 'AES-GCM' },
    true,
    ['decrypt']
  )
}

export function callOnStore (fn_) {
  // This works on all devices/browsers, and uses IndexedDBShim as a final fallback
  const indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB

  // Open (or create) the database
  const open = indexedDB.open('ninjaDB', 1)

  // Create the schema
  console.log(open)
  open.onupgradeneeded = function () {
    console.log((isset(() => open.result)), open.result)
    return (isset(() => open.result) ? open.result.createObjectStore('sessions', { keyPath: 'id' }) : null)
  }

  open.onsuccess = function () {
    // Start a new transaction
    const db = open.result
    const tx = db.transaction('sessions', 'readwrite')
    const store = tx.objectStore('sessions')

    fn_(store)

    // Close the db when the transaction is done
    tx.oncomplete = function () {
      db.close()
    }
  }
}

export function minimizedTextMore (event) {
  event.preventDefault()
  $(this).hide().prev().hide()
  $(this).next().show()
}

export function minimizedTextLess (event) {
  event.preventDefault()
  $(this).parent().hide().prev().show().prev().show()
}

export function minimizedText (el, maxlength) {
  const t = el.text()
  if (t.length < maxlength) return false

  $(el).html(
    t.slice(0, maxlength) + '<span>... </span><a href="#" class="more">Mehr anzeigen</a>' +
    '<span style="display:none;">' + t.slice(maxlength, t.length) + ' <a href="#" class="less">Weniger anzeigen</a></span>'
  )

  $(el).find('a.more').click(minimizedTextMore)
  $(el).find('a.less').click(minimizedTextLess)
}

export function sessionCheckAdvertise (identifier, currentPath, callback, errorCB = null) {
  $.ajax(currentPath + 'backend/get.php?realm=session&type=adv-message', {
    method: 'POST',
    data: { session_identifier: identifier },
    success: callback,
    error: (errorCB != null
      ? errorCB
      : function (error) { console.log(error) }
    )
  })
}

export function sessionGetFromDB (identifier, currentPath, callback, checkAdv = true) {
  $.ajax(currentPath + 'backend/get.php?realm=current-user&type=session', {
    method: 'POST',
    data: { session_identifier: identifier },
    success: function (data) {
      if (isset(() => data) && isset(() => data.pub_key) && data.identifier === identifier) {
        const cbResult = {
          pubkey: data.pub_key,
          adv_message: false
        }

        if (checkAdv) {
          sessionCheckAdvertise(identifier, currentPath, function (advMessage) {
            cbResult.adv_message = advMessage
            callback(cbResult)
          })
        } else callback(cbResult)
      }
    },
    error: function (error) {
      console.log(error)
    }
  })
}

export function passwordValidate (passwordEl, passwordCheckEl, validateParentEl, submitBtnEl, passwordValue) {
  const isValid = PASS_CHECK_FULL.test($(passwordEl).val())
  Object.entries(PASS_CHECK).forEach(function ([condKey, condRegEx]) {
    if (condRegEx.test($(passwordEl).val())) {
      $(validateParentEl).find('.' + condKey).removeClass('red')
      $(validateParentEl).find('.' + condKey).addClass('teal')
    } else {
      $(validateParentEl).find('.' + condKey).removeClass('teal')
      $(validateParentEl).find('.' + condKey).addClass('red')
    }
  })

  if (passwordValue === $(passwordCheckEl).val() && isValid) {
    $(passwordEl).addClass('valid')
    $(passwordCheckEl).addClass('valid')
    $(submitBtnEl).removeClass('disabled')
  } else {
    $(passwordEl).removeClass('valid')
    $(passwordCheckEl).removeClass('valid')
    $(submitBtnEl).addClass('disabled')
  }
}

export function generateKey (type, length = 0) {
  switch (type) {
    case 'AES':
    case 'aes':
      return window.crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: (length >= 16 ? length : 256)
        },
        true,
        ['encrypt', 'decrypt']
      )

    case 'RSA':
    case 'rsa':
    default:
      return window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: (length >= 1024 ? length : 4096),
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: { name: 'SHA-256' }
        },
        true,
        ['encrypt', 'decrypt']
      )
  }
}

export function generateRandomValues (length = 16) {
  return window.crypto.getRandomValues(new Uint8Array(length))
}

export function generateSessionIdentifier (hashwasmObj, ivLength = 16) {
  return hashwasmObj.md5(
    Array.from(window.crypto.getRandomValues(new Uint8Array((ivLength >= 8 ? ivLength : 16))), function (dec) {
      return dec.toString(16).padStart(2, '0')
    }).join('')
  )
}

export function sessionIdValidate (sessionId, submitBtnEl, validateLength = 32) {
  validateLength = (validateLength > 0 ? validateLength : 32)
  if (sessionId.length === validateLength) $(submitBtnEl).removeClass('disabled')
  else $(submitBtnEl).addClass('disabled')
}

export function checkWebCrypto () {
  if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle) {
    window.crypto.subtle = window.crypto.webkitSubtle
  }
  if (!window.crypto || !window.crypto.subtle) {
    window.alert('Your browser does not support the Web Cryptography API! This page will not work.')
    return
  }

  return window.crypto.subtle
}

export function encryptStr (type, key, str) {
  if (key != null && str != null) {
    switch (type) {
      case 'AES':
      case 'aes':
        return encryptStrAES(key, str)

      case 'RSA':
      case 'rsa':
      default:
        return encryptStrRSA(key, str)
    }
  } else return null
}

export function encryptB64 (type, key, b64) {
  if (key != null && b64 != null) {
    switch (type) {
      case 'AES':
      case 'aes':
        return encryptStrAES(key, b64)

      case 'RSA':
      case 'rsa':
      default:
        return encryptStrRSA(key, b64)
    }
  } else return null
}

export function encryptAES (key, data) {
  if (key != null && data != null) {
    const tmpIv = generateRandomValues(12)
    return {
      iv: tmpIv,
      data: window.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: tmpIv
        },
        key,
        data
      )
    }
  } else return null
}

export function encryptStrAES (key, str) {
  if (key != null && str != null) {
    return encryptAES(key, str2ab(str))
  } else return null
}

export function encryptB64AES (key, b64) {
  if (key != null && b64 != null) {
    return encryptAES(key, b642ab(b64))
  } else return null
}

export function encryptRSA (key, data) {
  if (key != null && data != null) {
    return window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data)
  } else return null
}

export function encryptStrRSA (key, str) {
  if (key != null && str != null) {
    return encryptRSA(str2ab(str))
  } else return null
}

export function encryptB64RSA (key, b64) {
  if (key != null && b64 != null) {
    return encryptRSA(b642ab(b64))
  } else return null
}

export function decryptAES (dataEnc, decryptKey, decryptIv) {
  if (dataEnc != null && decryptKey != null && decryptIv != null) {
    return window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: decryptIv
      },
      decryptKey,
      dataEnc
    )
  } else return null
}

export function decryptStrAES (strEnc, decryptKey, decryptIv) {
  if (strEnc != null && decryptKey != null && decryptIv != null) {
    return decryptAES(str2ab(strEnc), decryptKey, decryptIv)
  } else return null
}

export function decryptB64AES (b64Enc, decryptKey, decryptIv) {
  if (b64Enc != null && decryptKey != null && decryptIv != null) {
    return decryptAES(b642ab(b64Enc), decryptKey, decryptIv)
  } else return null
}

export function decryptRSA (dataEnc, decryptKey) {
  if (dataEnc != null && decryptKey != null) {
    return window.crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      decryptKey,
      dataEnc
    )
  } else return null
}

export function decryptStrRSA (strEnc, decryptKey) {
  if (strEnc != null && decryptKey != null) {
    return decryptRSA(str2ab(strEnc), decryptKey)
  } else return null
}

export function decryptB64RSA (b64Enc, decryptKey) {
  if (b64Enc != null && decryptKey != null) {
    return decryptRSA(b642ab(b64Enc), decryptKey)
  } else return null
}

export function createLinkLi (linkContainerEl, sessionPasswordModal, currentPath, content, cssClass = '', handlerType = 'active', cssWaves = true, href = '#') {
  const classes = cssClass + (cssWaves ? ' waves-effect' : '')
  $(linkContainerEl).append('<li><a href="' + href + '" class="' + classes + '">' + content + '</a></li>')
  $(linkContainerEl).find('li a').click(function () {
    sessionLinkHandler($(this), sessionPasswordModal, currentPath, handlerType)
  })
}

export function sessionLinkHandler (linkEl, sessionPasswordModal, currentPath, type = 'active') {
  const sessionIdentifier = $(linkEl).text()
  const passwordModalEl = $('#session-open-modal')
  const passwordEl = $('#session_joinpass')
  console.log(sessionIdentifier)

  callOnStore(function (store) {
    const getData = store.get(sessionIdentifier)

    getData.onsuccess(async function () {
      switch (type) {
        case 'free':
          sessionCheckAdvertise(sessionIdentifier, currentPath, function (advMessage) {
            if (isset(() => advMessage) && isset(() => advMessage[0].encrypted_key) && isset(() => advMessage[0].encrypted_message) && advMessage[0].encrypted_key != null && advMessage[0].encrypted_message != null) {
              $(passwordModalEl).data('session-identifier', sessionIdentifier)
              sessionPasswordModal.options.onCloseEnd = function () {
                unwrapKey(getData.result.enc_privkey, $(passwordEl).val(), getData.result.sal, getData.result.iv).then(function (privkey) {
                  decryptMessage(privkey, advMessage[0].encrypted_key, advMessage[0].encrypted_message, function (message) {
                    store.put({
                      id: getData.result.id,
                      iv: getData.result.iv,
                      sal: getData.result.sal,
                      pkey: getData.result.pkey,
                      enc_privkey: getData.result.enc_privkey,
                      foreign_pkey: message.payload
                    }, sessionIdentifier)
                  })
                })
              }

              sessionPasswordModal.open()
            }
          })
          break

        case 'active':
        default:
          sessionGetFromDB(sessionIdentifier, function (session) {

          })
      }
    })
  })
}

export function createSession (identifier, currentPath, publicKey, callback, expire = 0, errorCB = null) {
  $.ajax(currentPath + 'backend/create.php?type=session', {
    method: 'POST',
    data: {
      session_identifier: identifier,
      session_public_key: JSON.stringify(publicKey),
      session_expire: expire
    },
    success: (callback instanceof Function ? callback : function (data) { console.log(data) }),
    error: (errorCB instanceof Function ? errorCB : function (error) { console.log(error) })
  })
}

export function createAdvertise (identifier, currentPath, cryptdata, callback, errorCB = null) {
  $.ajax(currentPath + 'backend/create.php?type=advertise', {
    method: 'POST',
    data: {
      session_identifier: identifier,
      encrypted_key: cryptdata.enc_key,
      encrypted_message: JSON.stringify(cryptdata.enc_message)
    },
    success: (callback instanceof Function ? callback : function (data) { console.log(data) }),
    error: (errorCB instanceof Function ? errorCB : function (error) { console.log(error) })
  })
}

export function getMessageSender (certificateData) {
  return {
    UserName: certificateData.name,
    Tag: certificateData.tag,
    Serial: certificateData.serial
  }
}

export function getCurrentUnixTime (unit = 's') {
  const time = new Date().getTime()

  switch (unit) {
    case 's':
    case 'seconds':
    default:
      return Math.floor(time / 1000)
  }
}

export function generateMessageObject (message, expire, certificateData) {
  const currentUnixTimeSeconds = Math.floor(new Date().getTime() / 1000)

  return {
    META: {
      Sender: getMessageSender(certificateData),
      Timestamp: currentUnixTimeSeconds,
      Expire: (expire > 0 ? currentUnixTimeSeconds + expire : null)
    },
    payload: message
  }
}

export function decryptMessage (privkey, cryptkey, cryptmsg, callback) {
  const cryptmsgO = JSON.parse(cryptmsg)
  const messageKey = unwrapAESKey(b642ab(cryptkey), privkey)
  const messageIv = decryptB64RSA(cryptmsgO.iv, privkey)

  Promise.all([messageKey, messageIv]).then(function ([mkey, miv]) {
    decryptB64AES(cryptmsgO.data, mkey, miv).then(function (message) {
      callback(JSON.parse(message))
    })
  })
}

export function encryptMessage (key, message, messageExpire, certificateData, callback) {
  generateKey('aes').then(function (messageKey) {
    // const currentUnixTimeSeconds = Math.floor(new Date().getTime() / 1000);
    const messageKeyEnc = wrapKey(messageKey, key, 'aes')
    const messageEnc = encryptStr(
      'aes',
      messageKey,
      JSON.stringify(generateMessageObject(message, messageExpire, certificateData))
    )
    const messageIvEnc = encryptStr('rsa', key, messageEnc.iv)

    Promise.all([messageKeyEnc, messageEnc.cryptmsg, messageIvEnc]).then(function ([cryptkey, cryptmsg, cryptiv]) {
      callback(Object.create({
        enc_key: ab2b64(cryptkey),
        enc_message: {
          iv: ab2b64(cryptiv),
          data: ab2b64(cryptmsg)
        }
      }))
    })
  })
}
