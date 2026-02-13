import { libc_addr } from 'download0/userland'
import { stats } from 'download0/stats-tracker'
import { fn, mem, BigInt, utils } from 'download0/types'
import { sysctlbyname } from 'download0/kernel'
import { lapse } from 'download0/lapse'
import { binloader_init } from 'download0/binloader'
import { checkJailbroken } from 'download0/check-jailbroken'

// لو libc_addr مش متعرفة، نحمل userland
if (typeof libc_addr === 'undefined') {
  include('userland.js')
}

// تحميل باقي السكربتات
include('stats-tracker.js')
include('binloader.js')
include('lapse.js')
include('kernel.js')
include('check-jailbroken.js')
include('stats-tracker.js')
include('netctrl_c0w_twins.js')
log('All scripts loaded')

// تحميل الإحصائيات
stats.load()

// تشغيل الصوت كما هو
const audio = new jsmaf.AudioClip()
audio.volume = 0.5
audio.open('file:///../download0/sfx/bgm.wav')

// واجهة بسيطة: خلفية فقط أثناء التشغيل
jsmaf.root.children.length = 0

const background = new Image({
  url: 'file:///../download0/img/www.png',
  x: 0,
  y: 0,
  width: 1920,
  height: 1080
})
jsmaf.root.children.push(background)

// حالة الجيلبريك الحالية
const is_jailbroken = checkJailbroken()

// =======================
// دوال مساعدة
// =======================

function is_exploit_complete () {
  fn.register(24, 'getuid', [], 'bigint')
  fn.register(585, 'is_in_sandbox', [], 'bigint')
  try {
    const uid = fn.getuid()
    const sandbox = fn.is_in_sandbox()
    if (!uid.eq(0) || !sandbox.eq(0)) {
      return false
    }
  } catch (e) {
    return false
  }
  return true
}

function write64 (addr, val) {
  mem.view(addr).setBigInt(0, new BigInt(val), true)
}

function read8 (addr) {
  return mem.view(addr).getUint8(0)
}

function malloc (size) {
  return mem.malloc(size)
}

function get_fwversion () {
  const buf = malloc(0x8)
  const size = malloc(0x8)
  write64(size, 0x8)
  if (sysctlbyname('kern.sdk_version', buf, size, 0, 0)) {
    const byte1 = Number(read8(buf.add(2)))
    const byte2 = Number(read8(buf.add(3)))
    const version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0')
    return version
  }
  return null
}

const FW_VERSION = get_fwversion()

if (FW_VERSION === null) {
  log('ERROR: Failed to determine FW version')
  throw new Error('Failed to determine FW version')
}

const compare_version = (a, b) => {
  const a_arr = a.split('.')
  const amaj = Number(a_arr[0])
  const amin = Number(a_arr[1])
  const b_arr = b.split('.')
  const bmaj = Number(b_arr[0])
  const bmin = Number(b_arr[1])
  return amaj === bmaj ? amin - bmin : amaj - bmaj
}

// =======================
// عرض النتيجة (نجاح / فشل)
// =======================

function showResult (success) {
  jsmaf.root.children.length = 0

  const result = new Image({
    url: success
      ? 'file:///../download0/img/ok.png'
      : 'file:///../download0/img/fail.png',
    x: 0,
    y: 0,
    width: 1920,
    height: 1080
  })

  jsmaf.root.children.push(result)
}

// دالة النجاح المصدّرة – تستخدم صورة ok.png
export function show_success () {
  setTimeout(() => {
    showResult(true)
    log('Logging Success...')
    stats.incrementSuccess()
  }, 2000)
}

// =======================
// NetCtrl wrapper
// =======================

function run_netctrl_once () {
  log('[netctrl_wrapper] starting netctrl_exploit()')
  try {
    netctrl_exploit()
    log('[netctrl_wrapper] netctrl_exploit() returned (no crash)')
    return true
  } catch (e) {
    log('[netctrl_wrapper] ERROR in netctrl_exploit(): ' + (e).message)
    return false
  }
}

function run_netctrl_with_retries (maxTries) {
  for (let i = 1; i <= maxTries; i++) {
    log('[netctrl_wrapper] Attempt ' + i + '/' + maxTries)
    const ok = run_netctrl_once()
    if (ok) {
      log('[netctrl_wrapper] Success on attempt ' + i)
      return true
    }
  }
  log('[netctrl_wrapper] All attempts failed')
  return false
}

// =======================
// المنطق الرئيسي
// =======================

if (!is_jailbroken) {
  const jb_behavior =
    (typeof CONFIG !== 'undefined' && typeof CONFIG.jb_behavior === 'number')
      ? CONFIG.jb_behavior
      : 0

  stats.incrementTotal()
  utils.notify(FW_VERSION + ' Detected!')

  let use_lapse = false
  let use_netctrl = false

  if (jb_behavior === 1) {
    use_netctrl = true
  } else if (jb_behavior === 2) {
    use_lapse = true
  } else {
    if (compare_version(FW_VERSION, '7.00') >= 0 &&
        compare_version(FW_VERSION, '12.02') <= 0) {
      use_lapse = true
    } else if (compare_version(FW_VERSION, '12.50') >= 0 &&
               compare_version(FW_VERSION, '13.00') <= 0) {
      use_netctrl = true
    }
  }

  // ===== Lapse =====
  if (use_lapse) {
    lapse()

    const start_time = Date.now()
    const max_wait_ms = 5000

    while (!is_exploit_complete()) {
      if (Date.now() - start_time > max_wait_ms) {
        showResult(false)
        throw new Error('Lapse timeout')
      }
    }

    show_success()

    try {
      binloader_init()
    } catch (e) {
      showResult(false)
      throw e
    }
  }

  // ===== NetCtrl =====
  if (use_netctrl) {
    const ok = run_netctrl_with_retries(3)
    if (!ok) {
      stats.incrementFailure()
      showResult(false)
    } else {
      show_success()
      try {
        binloader_init()
      } catch (e) {
        showResult(false)
        throw e
      }
    }
  }
} else {
  showResult(true)
}

// =======================
// binloader يدويًا
// =======================

export function run_binloader () {
  try {
    binloader_init()
  } catch (e) {
    showResult(false)
    throw e
  }
}
