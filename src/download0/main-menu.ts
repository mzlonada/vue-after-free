import { lang } from 'download0/languages'
import { libc_addr } from 'download0/userland'
import { fn, BigInt, mem } from 'download0/types'

;(function () {
  // تحميل اللغة (JS بعد الـ build)
  include('download0/languages.js')
  log(lang.loadingMainMenu)

  jsmaf.root.children.length = 0

  // ============================
  //  تشغيل الموسيقى
  // ============================
  if (typeof CONFIG !== 'undefined' && CONFIG.music) {
    const bgm = new jsmaf.AudioClip()
    bgm.volume = 0.5
    bgm.open('file:///../download0/sfx/bgm.wav')
    bgm.play()
  }

  // ============================
  //  الخلفية
  // ============================
  const background = new Image({
    url: 'file:///../download0/img/background.png',
    x: 0,
    y: 0,
    width: 1920,
    height: 1080
  })
  jsmaf.root.children.push(background)

  // ============================
  //  صور النجاح والفشل
  // ============================
  const successImg = new Image({
    url: 'file:///../download0/img/success_full.png',
    x: 0,
    y: 0,
    width: 1920,
    height: 1080,
    visible: false
  })
  jsmaf.root.children.push(successImg)

  const failImg = new Image({
    url: 'file:///../download0/img/fail_full.png',
    x: 0,
    y: 0,
    width: 1920,
    height: 1080,
    visible: false
  })
  jsmaf.root.children.push(failImg)

  // ============================
  //  قراءة الفيرجن
  // ============================
  function getFirmwareVersion () {
    try {
      fn.register(0x1A, 'sysctl', ['bigint', 'bigint', 'bigint', 'bigint', 'bigint'], 'bigint')

      const name = mem.malloc(32)
      const old = mem.malloc(32)
      const oldlen = mem.malloc(8)

      const str = 'kern.osrelease'
      for (let i = 0; i < str.length; i++) mem.view(name).setUint8(i, str.charCodeAt(i))
      mem.view(name).setUint8(str.length, 0)

      mem.view(oldlen).setUint32(0, 32, true)

      fn.sysctl(name, old, oldlen, new BigInt(0, 0), new BigInt(0, 0))

      let fw = ''
      for (let i = 0; i < 32; i++) {
        const c = mem.view(old).getUint8(i)
        if (c === 0) break
        fw += String.fromCharCode(c)
      }

      log('Detected FW: ' + fw)
      return fw
    } catch (e) {
      log('FW detection failed: ' + e.message)
      return '0.00'
    }
  }

  // ============================
  //  مقارنة الفيرجن
  // ============================
  function isGreaterThan_12_02 (fw) {
    const p = fw.split('.')
    const major = parseInt(p[0] || '0')
    const minor = parseInt(p[1] || '0')

    if (major < 12) return false
    if (major > 12) return true
    return minor > 2
  }

  // ============================
  //  عرض النجاح والفشل
  // ============================
  function showSuccess () {
    successImg.visible = true
    failImg.visible = false
  }

  function showFail () {
    failImg.visible = true
    successImg.visible = false
  }

  // ============================
  //  اختيار الاستغلال تلقائيًا
  // ============================
  function auto_select_exploit () {
    const fw = getFirmwareVersion()

    setTimeout(() => {
      try {
        if (isGreaterThan_12_02(fw)) {
          log('Auto-select: NetCtrl')
          include('download0/loader.js')   // ← JS بعد build
        } else {
          log('Auto-select: Lapse')
          include('download0/lapse.js')    // ← JS بعد build
        }

        // مفيش showSuccess هنا
        // النجاح الحقيقي يحصل من داخل loader.js
      } catch (e) {
        log('Exploit failed: ' + e.message)
        showFail()
      }
    }, 1500)
  }

  auto_select_exploit()

  log(lang.mainMenuLoaded)
})()
