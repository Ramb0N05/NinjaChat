import 'https://cdn.neuland.ninja/jquery/3-7-1/jquery-3.7.1.min.js'
const $ = window.jQuery = jQuery

/**
 * AJAX Callback
 * @typedef {function(*)}
 * @callback Common.AjaxCallback
 * @param {*} responseData
 */

/**
 * Common Library
 * @export
 * @class
 */
export class Common {
  /**
   * Current url path property
   * @static
   * @readonly
   * @type {string}
   * @memberof Session
   */
  static get currentPath () {
    return window.location.origin + window.location.pathname
  }

  static get PASS_CHECK_LENGTH () { return 12 }
  static get PASS_CHECK_FULL () { return new RegExp('^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])(?=.*?[!@#$%^&*=€])(?=.{' + this.PASS_CHECK_LENGTH + ',})') }
  static get PASS_CHECK () {
    return {
      Numeric: /^(?=.*[0-9])/,
      Alpha: /^(?=.*[A-Z])(?=.*[a-z])/,
      Special: /^(?=.*?[!@#$%^&*=€])/,
      Length: new RegExp('^(?=.{' + this.PASS_CHECK_LENGTH + '})')
    }
  }

  /**
   * Get the current UNIX time
   * @static
   * @param {string} [unit='seconds'] Accepts 'hours' ('h'), 'minutes' ('m', 'min'), 'seconds' ('s', 'sec') or 'milliseconds' ('ms')
   * @returns {number}
   * @memberof Common
   */
  static getCurrentUnixTime (unit = 'seconds') {
    const time = new Date().getTime()

    switch (unit) {
      case 'ms':
      case 'milliseconds':
        return time
      case 'h':
      case 'hours':
        return Math.floor(time / 3600000)
      case 'm':
      case 'min':
      case 'minutes':
        return Math.floor(time / 60000)
      case 's':
      case 'sec':
      case 'seconds':
      default:
        return Math.floor(time / 1000)
    }
  }

  /**
   * Check if acessor is defined
   * @static
   * @param {*} accessor
   * @return {boolean}
   * @memberof Common
   */
  static isset (...accessors) {
    try {
      if (accessors.length > 0) {
        let isset = true
        accessors.forEach((accessor) => {
          if (accessor() === undefined || accessor() === null) isset = false
        })
        return isset
      } else return false
    } catch (e) {
      return false
    }
  }

  /**
   * Converts an ArrayBuffer to a Base64 string
   * @param {BufferSource} buffer
   * @returns {(string|false)}
   */
  static ab2b64 (buf) {
    if (Common.isBufferSource(buf)) {
      let binary = ''
      const bytes = new Uint8Array(buf)
      const len = bytes.byteLength
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i])
      }
      return window.btoa(binary)
    } else return false
  }

  /**
   * Converts a Base64 string to an ArrayBuffer
   * @param {string} base64
   * @returns {(ArrayBuffer|false)}
   */
  static b642ab (base64) {
    if (Common.isString(base64) && !Common.isEmpty(base64)) {
      const binaryString = window.atob(base64)
      const len = binaryString.length
      const bytes = new Uint8Array(len)
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i)
      }
      return bytes.buffer
    } else return false
  }

  /**
   * Converts a BufferSource to a string
   * @param {BufferSource} buf
   * @returns {string|false}
   */
  static ab2str (buf) {
    if (Common.isBufferSource(buf)) {
      const decoder = new TextDecoder()
      return decoder.decode(buf)
    } else return false
  }

  /**
   * Encodes a given string to an ArrayBuffer
   * @param {string} str
   * @returns {(ArrayBuffer|false)}
   */
  static str2ab (str) {
    if (Common.isString(str) && !Common.isEmpty(str)) {
      const encoder = new TextEncoder()
      return encoder.encode(str)
    } else return false
  }

  /**
   * Checks if data is a BufferSource
   * @param {*} data
   */
  static isBufferSource (data) {
    return (
      data instanceof ArrayBuffer ||
      data instanceof Uint8Array || data instanceof Uint8ClampedArray || data instanceof Uint16Array || data instanceof BigUint64Array ||
      data instanceof Int8Array || data instanceof Int16Array || data instanceof Int32Array || data instanceof BigInt64Array ||
      data instanceof Float32Array || data instanceof Float64Array
    )
  }

  /**
   * Checks if a given string is Base64 encoded
   * @param {string} data
   * @param {boolean} validate
   * @returns {boolean}
   */
  static isBase64 (data, validate = false) {
    if (Common.isString(data) && !Common.isEmpty(data)) {
      try {
        if (validate === true) {
          return (window.btoa(window.atob(data)) === data)
        } else {
          window.atob(data)
          return true
        }
      } catch {
        return false
      }
    } else return false
  }

  /**
   * Checks if data is a string
   * @param {*} data
   * @returns {boolean}
   */
  static isString (data) {
    return (Object.prototype.toString.call(data) === '[object String]')
  }

  /**
   * Checks if data is empty
   * @param {*} data
   * @param {boolean} trim Check if data.trim() is a empty string
   * @returns {boolean}
   */
  static isEmpty (data, trim = true) {
    const empty = (
      !Common.isset(() => data) ||
      data === [] ||
      data === {} ||
      data === ''
    )

    if (trim) return (empty || (Common.isString(data) && data.trim() === ''))
    else return empty
  }

  /**
   * Checks if two given containers are colliding
   * @param {HTMLElement|$} div1
   * @param {HTMLElement|$} div2
   */
  static isColliding (div1, div2) {
    if (div1 instanceof window.HTMLElement) div1 = $(div1)
    if (div2 instanceof window.HTMLElement) div2 = $(div2)
    div1 = (div1 instanceof $ ? div1 : null)
    div2 = (div2 instanceof $ ? div2 : null)

    // Div 1 data
    const d1Offset = div1.offset()
    const d1Height = div1.outerHeight(true)
    const d1Width = div1.outerWidth(true)
    const d1DistanceFromTop = d1Offset.top + d1Height
    const d1DistanceFromLeft = d1Offset.left + d1Width

    // Div 2 data
    const d2Offset = $(div2).offset()
    const d2Height = div2.outerHeight(true)
    const d2Width = div2.outerWidth(true)
    const d2DistanceFromTop = d2Offset.top + d2Height
    const d2DistanceFromLeft = d2Offset.left + d2Width

    const notColliding = (d1DistanceFromTop < d2Offset.top || d1Offset.top > d2DistanceFromTop || d1DistanceFromLeft < d2Offset.left || d1Offset.left > d2DistanceFromLeft)

    // Return whether it IS colliding
    return !notColliding
  }

  /**
   * Calls a callback function
   * @param {Common.AjaxCallback} callback
   * @param {*} [data=null]
   * @param {boolean} [logFallback=true]
   */
  static callCallback (callback, data = null, logFallback = true) {
    if (callback instanceof Function) {
      if (Common.isset(() => data)) callback(data)
      else callback()
    } else if (logFallback === true) console.log(data)
  }

  /**
   * Perform a jQuery AJAX Request
   * @static
   * @param {string} url
   * @param {(object|null)} [dataObject=null]
   * @param {string} [methodStr='GET']
   * @param {(Common.AjaxCallback|null)} [successCallback=null]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Common
   */
  static ajax (url, dataObject = null, methodStr = 'GET', successCallback = null, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    if (Common.isString(url) && !Common.isEmpty(url)) {
      if (!Common.isset(() => dataObject)) dataObject = null
      if (
        !Common.isset(() => methodStr) || !Common.isString(methodStr) || Common.isEmpty(methodStr) ||
        (methodStr !== 'POST' && methodStr !== 'PUT')
      ) methodStr = 'GET'

      $.ajax(
        url,
        {
          method: methodStr,
          data: dataObject,
          success: (result) => { Common.callCallback(successCallback, result, logOnSuccessFallback) },
          error: (error) => { Common.callCallback(errorCallback, error, logOnErrorFallback) }
        }
      )
    } else Common.callCallback(errorCallback, 'ERROR: no url given', logOnErrorFallback)
  }

  /**
   * Perform a simple jQuery AJAX Request
   * @static
   * @param {string} url
   * @param {(Common.AjaxCallback|null)} [successCallback=null]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Common
   */
  static ajax0 (url, successCallback = null, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    Common.ajax(url, null, null, successCallback, errorCallback, logOnSuccessFallback, logOnErrorFallback)
  }

  /**
   * Perform a jQuery AJAX Request using POST
   * @static
   * @param {string} url
   * @param {object} dataObject
   * @param {(Common.AjaxCallback|null)} [successCallback=null]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Common
   */
  static ajaxPOST (url, dataObject, successCallback = null, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    Common.ajax(url, dataObject, 'POST', successCallback, errorCallback, logOnSuccessFallback, logOnErrorFallback)
  }

  /**
   * Perform a jQuery AJAX Request using PUT
   * @static
   * @param {string} url
   * @param {object} dataObject
   * @param {(Common.AjaxCallback|null)} [successCallback=null]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Common
   */
  static ajaxPUT (url, dataObject, successCallback = null, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    Common.ajax(url, dataObject, 'PUT', successCallback, errorCallback, logOnSuccessFallback, logOnErrorFallback)
  }

  /**
   * Perform a jQuery AJAX Request using GET
   * @static
   * @param {string} url
   * @param {object} dataObject
   * @param {(Common.AjaxCallback|null)} [successCallback=null]
   * @param {(Common.AjaxCallback|null)} [errorCallback=null]
   * @param {boolean} [logOnSuccessFallback=false]
   * @param {boolean} [logOnErrorFallback=true]
   * @memberof Common
   */
  static ajaxGET (url, dataObject, successCallback = null, errorCallback = null, logOnSuccessFallback = false, logOnErrorFallback = true) {
    Common.ajax(url, dataObject, 'GET', successCallback, errorCallback, logOnSuccessFallback, logOnErrorFallback)
  }

  /**
   * Validates a given password and handles the presentation of the security criteria information
   * @param {($|HTMLElement|string)} passwordEl
   * @param {($|HTMLElement|string)} passwordCheckEl
   * @param {($|HTMLElement|string)} validateParentEl
   * @param {($|HTMLElement|string)} submitBtnEl
   * @param {string} passwordValue
   * @returns {boolean}
   */
  static validatePassword (passwordEl, passwordCheckEl, validateParentEl = null, submitBtnEl = null) {
    if (Common.isString(passwordEl) || passwordEl instanceof window.HTMLElement) passwordEl = $(passwordEl)
    if (Common.isString(passwordCheckEl) || passwordCheckEl instanceof window.HTMLElement) passwordCheckEl = $(passwordCheckEl)
    passwordEl = (passwordEl instanceof $ ? passwordEl : null)
    passwordCheckEl = (passwordCheckEl instanceof $ ? passwordCheckEl : null)

    if (passwordEl !== null && passwordCheckEl !== null) {
      const isValid = this.PASS_CHECK_FULL.test($(passwordEl).val())

      if (Common.isString(validateParentEl) || validateParentEl instanceof window.HTMLElement) validateParentEl = $(validateParentEl)
      if (Common.isString(submitBtnEl) || submitBtnEl instanceof window.HTMLElement) submitBtnEl = $(submitBtnEl)
      validateParentEl = (validateParentEl instanceof $ ? validateParentEl : null)
      submitBtnEl = (submitBtnEl instanceof $ ? submitBtnEl : null)

      if (validateParentEl !== null) {
        Object.entries(this.PASS_CHECK).forEach(function ([condKey, condRegEx]) {
          if (condRegEx.test($(passwordEl).val())) {
            $(validateParentEl).find('.' + condKey).removeClass('red')
            $(validateParentEl).find('.' + condKey).addClass('teal')
          } else {
            $(validateParentEl).find('.' + condKey).removeClass('teal')
            $(validateParentEl).find('.' + condKey).addClass('red')
          }
        })
      }

      if ($(passwordEl).val() === $(passwordCheckEl).val() && isValid) {
        $(passwordEl).addClass('valid')
        $(passwordCheckEl).addClass('valid')
        if (submitBtnEl !== null) $(submitBtnEl).removeClass('disabled')
      } else {
        $(passwordEl).removeClass('valid')
        $(passwordCheckEl).removeClass('valid')
        if (submitBtnEl !== null) $(submitBtnEl).addClass('disabled')
      }

      return isValid
    } else return false
  }
}
