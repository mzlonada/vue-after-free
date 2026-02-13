import { lang } from 'download0/languages'
import { libc_addr } from 'download0/userland'
import { fn, BigInt, mem } from 'download0/types'

;(function () {
  include('languages.ts')
  log(lang.loadingMainMenu)

  jsmaf.root.children.length = 0

  // ============================
  //  تشغيل الصوت القديم (bgm.wav)
  // ============================
  if (typeof CONFIG !== 'undefined' && CONFIG.music) {
    const bgm = new jsmaf.AudioClip()
    bgm.volume = 0.5
    bgm.open('file:///../download0/sfx/bgm.wav')
    bgm.play()
  }

  // ============================
  //  الخلفية (ملء الشاشة)
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
  //  صورة النجاح (ملء الشاشة)
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

  // ============================
  //  صورة الفشل (ملء الشاشة)
  // ============================
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
  //  قراءة الفيرجن من kern.osrelease
  // ============================
  function getFirmwareVersion () {
    try {
      fn.register(0x1A, 'sysctl', ['bigint','bigint','bigint','bigint','bigint'], 'bigint')

      const name = mem.malloc(32)
      const old = mem.malloc(32)
      const oldlen = mem.malloc(8)

      const str = 'kern.osrelease'
      for (let i = 0; i < str.length; i++) mem.view(name).setUint8(i, str.charCodeAt(i))
      mem.view(name).setUint8(str.length, 0)

      mem.view(oldlen).setUint32(0, 32, true)

      fn.sysctl(name, old, oldlen, new BigInt(0,0), new BigInt(0,0))

      let fw = ""
      for (let i = 0; i < 32; i++) {
        const c = mem.view(old).getUint8(i)
        if (c === 0) break
        fw += String.fromCharCode(c)
      }

      log("Detected FW: " + fw)
      return fw
    } catch(e) {
      log("FW detection failed: " + e.message)
      return "0.00"
    }
  }

  // ============================
  //  مقارنة الفيرجن
  //  FW <= 12.02 → Lapse
  //  FW > 12.02 → NetCtrl
  // ============================
  function isGreaterThan_12_02(fw) {
    const p = fw.split(".")
    const major = parseInt(p[0] || "0")
    const minor = parseInt(p[1] || "0")

    if (major < 12) return false
    if (major > 12) return true
    return minor > 2
  }

  // ============================
  //  عرض النجاح
  // ============================
  function showSuccess() {
    successImg.visible = true
    failImg.visible = false
  }

  // ============================
  //  عرض الفشل
  // ============================
  function showFail() {
    failImg.visible = true
    successImg.visible = false
  }

  // ============================
  //  تشغيل الاستغلال تلقائيًا
  // ============================
  function auto_select_exploit() {
    const fw = getFirmwareVersion()

    setTimeout(() => {
      try {
        if (isGreaterThan_12_02(fw)) {
          log("Auto-select: NetCtrl")
          include("loader.ts")   // NetCtrl exploit
        } else {
          log("Auto-select: Lapse")
          include("lapse.ts")    // Lapse exploit
        }

        // لو مفيش خطأ → نجاح
        showSuccess()

      } catch(e) {
        log("Exploit failed: " + e.message)
        showFail()
      }

    }, 1500)
  }

  auto_select_exploit()

  log(lang.mainMenuLoaded)
})()