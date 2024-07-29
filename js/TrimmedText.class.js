import 'https://cdn.neuland.ninja/jquery/3-7-1/jquery-3.7.1.min.js'
import { Common } from './Common.class.js'
const $ = window.jQuery = jQuery

/**
 * @class TrimmedText
 * @export
 */
export class TrimmedText {
  /**
   * Creates an instance of TrimmedText
   * @param {($|Element|string)} textareaEl
   * @param {boolean} [silent=false]
   * @param {number} [maxLength=300]
   * @param {string} [moreSuffix='Mehr anzeigen']
   * @param {string} [lessSuffix='Weniger anzeigen']
   * @memberof TrimmedText
   */
  constructor (textareaEl, silent = false, maxLength = 300, moreSuffix = 'Mehr anzeigen', lessSuffix = 'Weniger anzeigen') {
    if (Common.isString(textareaEl) || textareaEl instanceof window.Element) textareaEl = $(textareaEl)
    this.element = (textareaEl instanceof $ ? textareaEl : null)
    this.maxLength = (!isNaN(maxLength) ? maxLength : 300)
    this.moreSuffix = (Common.isString(moreSuffix) ? moreSuffix : 'Mehr anzeigen')
    this.lessSuffix = (Common.isString(lessSuffix) ? lessSuffix : 'Mehr anzeigen')

    if (silent !== true) this.update()
  }

  /**
   * element Property
   * @type {$}
   * @memberof TrimmedText
   */
  get Element () { return this.element }
  set Element (value) { this.element = (value instanceof window.Element ? value : null) }

  /**
   * maxLength Property
   * @type {number}
   * @memberof TrimmedText
   */
  get MaxLength () { return this.maxLength }
  set MaxLength (value) { this.maxLength = (!isNaN(value) ? value : 300) }

  /**
   * moreSuffix Property
   * @type {string}
   * @memberof TrimmedText
   */
  get MoreSuffix () { return this.moreSuffix }
  set MoreSuffix (value) { this.moreSuffix = (Common.isString(value) ? value : 'Mehr anzeigen') }

  /**
   * lessSuffix Property
   * @type {string}
   * @memberof TrimmedText
   */
  get LessSuffix () { return this.lessSuffix }
  set LessSuffix (value) { this.lessSuffix = (Common.isString(value) ? value : 'Weniger anzeigen') }

  /**
   * ShowMoreText Handler
   * @static
   * @param {*} event
   * @memberof TrimmedText
   */
  static moreHandler (event) {
    event.preventDefault()
    $(this).hide().prev().hide()
    $(this).next().show()
  }

  /**
   * ShowLessText Handler
   * @static
   * @param {*} event
   * @memberof TrimmedText
   */
  static lessHandler (event) {
    event.preventDefault()
    $(this).parent().hide().prev().show().prev().show()
  }

  /**
   * Updates the handlers of the more-text or less-text links
   * @memberof TrimmedText
   */
  update () {
    const content = $(this.element).text()

    if (Common.isString(content) && content.length > this.maxLength && $(this.element).data('trimmed') !== 'true') {
      $(this.element).html(
        content.slice(0, this.maxlength) + '<span>... </span><a href="#" class="more">' + this.moreSuffix + '</a>' +
        '<span style="display:none;">' + content.slice(this.maxlength, content.length) + ' <a href="#" class="less">' + this.lessSuffix + '</a></span>'
      )

      $(this.element).data('trimmed', 'true')
      $(this.element).find('a.more').on('click', TrimmedText.moreHandler)
      $(this.element).find('a.less').on('click', TrimmedText.lessHandler)
    }
  }
}

/**
 * @export
 * @class TrimmedTextList
 */
export class TrimmedTextList {
  /**
   * Creates an instance of TrimmedTextList
   * @param {string} textareaElementsSelector
   * @param {number} [maxlength=300]
   * @param {string} [moreSuffix='Mehr anzeigen']
   * @param {string} [lessSuffix='Weniger anzeigen']
   * @memberof TrimmedTextList
   */
  constructor (textareaElementsSelector, silent = false, maxLength = 300, moreSuffix = 'Mehr anzeigen', lessSuffix = 'Weniger anzeigen') {
    this.elementsSelector = (Common.isString(textareaElementsSelector) ? textareaElementsSelector : null)
    this.maxLength = maxLength
    this.moreSuffix = (Common.isString(moreSuffix) ? moreSuffix : 'Mehr anzeigen')
    this.lessSuffix = (Common.isString(lessSuffix) ? lessSuffix : 'Mehr anzeigen')
    this.create(this.elementsSelector, silent)
  }

  /**
   * list Property
   * @type {Array<TrimmedText>}
   * @memberof TrimmedTextList
   */
  get List () { return this.list }
  set List (value) { this.list = (value instanceof Array) ? value : [] }

  /**
   * element Property
   * @type {string}
   * @memberof TrimmedTextList
   */
  get ElementsSelector () { return this.elementsSelector }
  set ElementsSelector (value) { this.elementsSelector = (Common.isString(value) ? value : null) }

  /**
   * maxLength Property
   * @type {number}
   * @memberof TrimmedTextList
   */
  get MaxLength () { return this.maxLength }
  set MaxLength (value) { this.maxLength = (!isNaN(value) ? value : 300) }

  /**
   * moreSuffix Property
   * @type {string}
   * @memberof TrimmedTextList
   */
  get MoreSuffix () { return this.moreSuffix }
  set MoreSuffix (value) { this.moreSuffix = (Common.isString(value) ? value : 'Mehr anzeigen') }

  /**
   * lessSuffix Property
   * @type {string}
   * @memberof TrimmedTextList
   */
  get LessSuffix () { return this.lessSuffix }
  set LessSuffix (value) { this.lessSuffix = (Common.isString(value) ? value : 'Weniger anzeigen') }

  /**
   * Updates all textareas
   * @memberof TrimmedTextList
   */
  updateAll () {
    this.list.forEach((tta) => tta.update())
  }

  /**
   * Creates the collection (Alias of TrimmedTextList.recreate)
   * @param {(string|null)} [textareaElementsSelector=null]
   * @param {boolean} [silent=false]
   * @memberof TrimmedTextList
   */
  create (textareaElementsSelector = null, silent = false) {
    this.recreate(textareaElementsSelector, silent)
  }

  /**
   * Recreates the collection
   * @param {(string|null)} [textareaElementsSelector=null]
   * @param {boolean} [silent=false]
   * @memberof TrimmedTextList
   */
  recreate (textareaElementsSelector = null, silent = false) {
    const textareaElements = (Common.isString(textareaElementsSelector) ? $(textareaElementsSelector) : this.elementsSelector)

    this.list = []
    $(textareaElements).each((i, el) => {
      this.list.push(new TrimmedText(el, silent, this.maxLength, this.moreSuffix, this.lessSuffix))
    })
  }
}
