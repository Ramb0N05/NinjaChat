// import 'https://cdn.neuland.ninja/hash-wasm.js'
import 'https://cdn.neuland.ninja/jquery/3-7-1/jquery-3.7.1.min.js'
// import 'https://cdn.neuland.ninja/jquery/jquery.visible.min.js'
import 'https://cdn.neuland.ninja/materializecss/2-0-3_alpha/js/materialize.es6.js'
// import * as C from 'https://cdn.neuland.ninja/misc/colliding.module.js'
import * as I from './functions.js'
import { Common } from './js/Common.class.js'
import { Session } from './js/Session.class.js'
import { Security } from './js/Security.class.js'
import { IDBStorage } from './js/IDBStorage.class.js'
import { TrimmedTextList, TrimmedText } from './js/TrimmedText.class.js'
import { Message } from './js/Message.class.js'

const TT_MAXLENGTH_DEFAULT = 300
const TT_MAXLENGTH_MOBILE = 150

const $ = window.jQuery = jQuery
const M = window.M
const IDB = new IDBStorage('ninjaDB')
const S = Security.Init(true)

const isMobile = (window.screen.width <= 992)
const textMaxLength = (isMobile ? TT_MAXLENGTH_MOBILE : TT_MAXLENGTH_DEFAULT)
const keypressStore = []
const currentPath = window.location.origin + window.location.pathname
let CERT = false

$(function () {
  M.AutoInit()
  M.Sidenav.init($('.sidenav'))
  $('select').formSelect()
  $('input[type="range"]').range()

  const ttlist = new TrimmedTextList('#chat-body .card-panel:last-child > pre', true, textMaxLength)

  Common.ajax0(currentPath + 'backend/get.php?realm=current-user&type=cert-info', function (data) {
    CERT = data
    $('#slide-out .name').text(data.name)
    $('#slide-out  .email').text(data.tag)

    if (Common.isColliding($('#slide-out .user-info'), $('#slide-out .user i'))) {
      $('#slide-out .user').css('text-align', 'right')
    }
  })

  IDB.call('sessions', function (store) {
    store.openCursor().onsuccess = function (event) {
      const cur = event.target.result
      if (cur) {
        const getData = store.get(cur.key)

        getData.onsuccess = async function () {
          const newSession = new Session(getData.result.id)

          newSession.retrieve(function (session) {
            if (Common.isset(() => session, () => session.pubkey, () => session.adv_message, () => session.adv_message[0])) {
              if (session.adv_message[0] === false) {
                newSession.createLinkListItem('#sessions-free .collapsible-body', '#session-open-modal', IDB, 'free-session-link', 'free')
              } else if (Common.isset(() => session.adv_message[0].encrypted_key, () => session.adv_message[0].encrypted_message)) {
                newSession.createLinkListItem('#sessions-free .collapsible-body', '#session-open-modal', IDB, 'active-session-link', 'active')
              }
            }
          })
        }

        cur.continue()
      }
    }
  })

  if (!$('#message').val().trim()) {
    $('#invisible-data').data('original-input-height', $('#chat-footer .input-field').height())
    $('#invisible-data').data('original-height', $('#message').height())
  }

  $('.sidenav-toggle').on('click', function () {
    const targetEl = $('#' + $(this).data('target'))
    const targetIn = M.Sidenav.getInstance(targetEl)

    if (targetIn.isOpen) targetIn.close()
    else targetIn.open()
  })

  $('.bg-item').on('click', function () {
    const name = $(this).data('name')
    // const opacityData = $(this).data('opacity')
    window.alert(name)
    $('#chat-bg').animate({ opacity: 0 }, 'slow', function () {
      $(this)
        .css(
          { 'background-image': 'url(./img/bg/' + name + '.png)' }
        )
        .animate(
          { opacity: 1 },
          'slow'
        )
    })

    // $('#chat-bg').animate({opacity: 0}, 'slow')
    // $('#chat-bg').css('background-image', 'url("./img/bg/' + name + '.png")')
    // $('#chat-bg').animate({opacity: opacityData}, 'slow')
  })

  const submitMessageF = function () {
    const inputEl = $('#chat-footer .input-field')
    const msgEl = $('#message')
    const dataEl = $('#invisible-data')
    const msg = msgEl.val().trim()

    if (msg) {
      $('#chat-body').append('<div class="card-panel own right"><pre>' + msg + '</pre></div>')
      ttlist.recreate()
      $('#chat-body').animate({ scrollTop: $('#chat-body').prop('scrollHeight') }, 1000)

      msgEl.val('')
      inputEl.height(dataEl.data('original-input-height'))
      msgEl.height(dataEl.data('original-height'))
      msgEl.next('label').removeClass('active')

      console.log(dataEl.data())
    }
  }

  $('#submit-message-btn').on('click', function () {
    submitMessageF()
    if ($('#message').val()) $('#message').next('label').hide()
    else $('#message').next('label').show()
  })

  $('#message').on('keydown', function (event) {
    const keycode = (event.keyCode ? event.keyCode : event.which)
    keypressStore[keycode] = true

    if ($(this).val()) $(this).next('label').hide()
    else $(this).next('label').show()

    if (!keypressStore[16] && !isMobile && keycode === '13') {
      event.preventDefault()
      submitMessageF()
    }
  })

  $('#message').on('keyup', function (event) {
    delete keypressStore[(event.keyCode ? event.keyCode : event.which)]

    if ($(this).val()) $(this).next('label').hide()
    else $(this).next('label').show()
  })

  $('#chat-body .card-panel > pre').each(function () {
    ttlist.recreate()
  })

  $('#main-fab a').on('click', function () {
    M.Modal.getInstance($('#session-add-modal')).open()
  })

  $('#session-join-btn').on('click', function () {
    const identifier = $('#session_id').val()
    const sessionJoinPassword = $('#session_join_password').val()
    const newSession = new Session(identifier)

    newSession.retrieve((session) => {
      if (Common.isset(() => session, () => session.pubkey, () => session.adv_message, () => session.adv_message[0]) && session.adv_message[0] === false && !!CERT && S instanceof Security) {
        const newKey = S.createKeyPairAsync(4096)
        if (newKey instanceof Security.KeyPair) {
          const privateKeyW = S.wrapRSAKeyWithPasswordAsync(newKey.privateKey, sessionJoinPassword)
          const publicKeyExport = S.exportKeyAsync(newKey.publicKey, true, true)
          const sessionPublicKey = S.importKeyAsync(
            session.pubkey,
            {
              name: 'RSA-OAEP',
              hash: 'SHA-256'
            },
            true,
            ['encrypt']
          )

          const encryptedMessage = Message.encryptAsync(sessionPublicKey, publicKeyExport, 600, CERT)
          if (encryptedMessage instanceof Message.EncryptedMessageDataObject && privateKeyW instanceof Security.AESEncryptedObject) {
            newSession.createAdvertise(encryptedMessage, (result) => {
              newSession.createLinkListItem('#sessions-active .collapsible-body', '#session-open-modal', IDB, 'active-session-link', 'free')
            })

            IDB.call('sessions', (store) => {
              store.put({
                id: newSession.identifier,
                iv: privateKeyW.iv,
                sal: privateKeyW.salt,
                pkey: publicKeyExport,
                enc_privkey: privateKeyW.encrypted.valueBase64
              })
            })
          }
        }
      }
    })
  })

  $('#session_id').on('keyup', function () { Session.validateIdentifier($(this).val(), '#session-join-btn') })
  $('#session_id').on('keydown', function () { Session.validateIdentifier($(this).val(), '#session-join-btn') })

  $('#session-create-btn').on('click', async function () {
    let sessionExpire = parseInt($('#session_expire').val(), 10)
    sessionExpire = (isNaN(sessionExpire) && sessionExpire <= 24 && sessionExpire >= 1 ? sessionExpire : 24) * 3600
    const sessionPassword = $('#session_password').val()
    const validPassword = Common.validatePassword('#session_password', '#session_password_check')

    if (validPassword === true) {
      const sessionIdentifier = await Session.generateIdentifierAsync()
      const newKey = await S.createKeyPair(4096)

      if (newKey instanceof Security.KeyPair && S instanceof Security) {
        const newSession = new Session(sessionIdentifier, newKey.PublicKey, sessionExpire)
        const publicKeyExport = await S.exportKeyAsync(newKey.PublicKey, true, true)
        const privateKeyW = await S.wrapRSAKeyWithPasswordAsync(newKey.PrivateKey, sessionPassword)

        if (privateKeyW !== false) {
          IDB.call('sessions', (store) => {
            store.put({
              id: newSession.Identifier,
              iv: privateKeyW.IV.ValueBase64,
              sal: privateKeyW.Salt.ValueBase64,
              pkey: publicKeyExport,
              enc_privkey: privateKeyW.Encrypted.ValueBase64
            })
          })

          newSession.create(() => {
            newSession.createLinkListItem('#sessions-free .collapsible-body', '#session-open-modal', IDB, 'free-session-link', 'free')
          })
        } else window.alert('ERROR: Session could not be created!')
      }
    }
  })

  $('#session_password').on('keydown', function () {
    Common.validatePassword(this, '#session_password_check', '#session-create-validate', '#session-create-btn')
  })

  $('#session_password').on('keyup', function () {
    Common.validatePassword(this, '#session_password_check', '#session-create-validate', '#session-create-btn')
  })

  $('#session_password_check').on('keydown', function () {
    Common.validatePassword('#session_password', this, '#session-create-validate', '#session-create-btn')
  })

  $('#session_password_check').on('keyup', function () {
    Common.validatePassword('#session_password', this, '#session-create-validate', '#session-create-btn')
  })

  $('#session_join_password').on('keydown', function () {
    Common.validatePassword(this, '#session_join_password_check', '#session-join-validate', '#session-join-btn')
  })

  $('#session_join_password').on('keyup', function () {
    Common.validatePassword(this, '#session_join_password_check', '#session-join-validate', '#session-join-btn')
  })

  $('#session_join_password_check').on('keydown', function () {
    Common.validatePassword('#session_join_password', this, '#session-join-validate', '#session-join-btn')
  })

  $('#session_join_password_check').on('keyup', function () {
    Common.validatePassword('#session_join_password', this, '#session-join-validate', '#session-join-btn')
  })
})
