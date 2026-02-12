import { libc_addr } from 'download0/userland'
import { stats } from 'download0/stats-tracker'
import { fn, mem, BigInt, utils } from 'download0/types'
import { sysctlbyname } from 'download0/kernel'
import { lapse } from 'download0/lapse'
import { binloader_init } from 'download0/binloader'
import { checkJailbroken } from 'download0/check-jailbroken'

// لو هنستخدم NetCtrl لازم نضمن تحميله هنا مرة واحدة
include('netctrl_c0w_twins.js')

// === netctrl wrapper مدمج داخل اللودر بدل ملف جديد ===

function run_netctrl_once (): boolean {
  log('[netctrl_wrapper] starting netctrl_exploit()')
  try {
    // الدالة الأصلية من netctrl_c0w_twins.js
    // لازم تكون متاحة في السياق العالمي
    // @ts-expect-error
    netctrl_exploit()
    log('[netctrl_wrapper] netctrl_exploit() returned (no crash)')
    return true
  } catch (e) {
    log('[netctrl_wrapper] ERROR in netctrl_exploit(): ' + (e as Error).message)
    return false
  }
}

function run_netctrl_with_retries (maxTries: number): boolean {
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

// =====================================================
// تحميل باقي السكربتات
// =====================================================

// Check if libc_addr is defined
if (typeof libc_addr === 'undefined') {
  include('userland.js')
}
include('stats-tracker.js')
include('binloader.js')
include('lapse.js')
include('kernel.js')
include('check-jailbroken.js')
include('stats-tracker.js')
log('All scripts loaded')

// Increment total attempts
stats.load()

export function show_success () {
  setTimeout(() => {
    jsmaf.root.children.push(bg_success)
    log('Logging Success...')
    stats.incrementSuccess()
  }, 2000)
}

const audio = new jsmaf.AudioClip()
audio.volume = 0.5  // 50% volume
audio.open('file://../download0/sfx/bgm.wav')

const is_jailbroken = checkJailbroken()

// Check if exploit has completed successfully
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

function write64 (addr: BigInt, val: BigInt | number) {
  mem.view(addr).setBigInt(0, new BigInt(val), true)
}

function read8 (addr: BigInt) {
  return mem.view(addr).getUint8(0)
}

function malloc (size: number) {
  return mem.malloc(size)
}

function get_fwversion () {
  const buf = malloc(0x8)
  const size = malloc(0x8)
  write64(size, 0x8)
  if (sysctlbyname('kern.sdk_version', buf, size, 0, 0)) {
    const byte1 = Number(read8(buf.add(2)))  // Minor
    const byte2 = Number(read8(buf.add(3)))  // Major
    const version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0')
    return version
  }
  return null
}

const FW_VERSION: string | null = get_fwversion()

if (FW_VERSION === null) {
  log('ERROR: Failed to determine FW version')
  throw new Error('Failed to determine FW version')
}

const compare_version = (a: string, b: string) => {
  const a_arr = a.split('.')
  const amaj = Number(a_arr[0])
  const amin = Number(a_arr[1])
  const b_arr = b.split('.')
  const bmaj = Number(b_arr[0])
  const bmin = Number(b_arr[1])
  return amaj === bmaj ? amin - bmin : amaj - bmaj
}

if (!is_jailbroken) {
  const jb_behavior = (typeof CONFIG !== 'undefined' && typeof CONFIG.jb_behavior === 'number') ? CONFIG.jb_behavior : 0

  stats.incrementTotal()
  utils.notify(FW_VERSION + ' Detected!')

  let use_lapse = false
  let use_netctrl = false

  if (jb_behavior === 1) {
    log('JB Behavior: NetControl (forced)')
    use_netctrl = true
  } else if (jb_behavior === 2) {
    log('JB Behavior: Lapse (forced)')
    use_lapse = true
  } else {
    log('JB Behavior: Auto Detect')
    if (compare_version(FW_VERSION, '7.00') >= 0 && compare_version(FW_VERSION, '12.02') <= 0) {
      use_lapse = true
    } else if (compare_version(FW_VERSION, '12.50') >= 0 && compare_version(FW_VERSION, '13.00') <= 0) {
      use_netctrl = true
    }
  }

  // تشغيل Lapse لو متفعّل
  if (use_lapse) {
    lapse()

    const start_time = Date.now()
    const max_wait_seconds = 5
    const max_wait_ms = max_wait_seconds * 1000

    while (!is_exploit_complete()) {
      const elapsed = Date.now() - start_time
      if (elapsed > max_wait_ms) {
        log('ERROR: Timeout waiting for exploit to complete (' + max_wait_seconds + ' seconds)')
        throw new Error('Lapse timeout')
      }
      const poll_start = Date.now()
      while (Date.now() - poll_start < 500) {
        // busy wait
      }
    }

    show_success()
    const total_wait = ((Date.now() - start_time) / 1000).toFixed(1)
    log('Exploit completed successfully after ' + total_wait + ' seconds')

    log('Initializing binloader...')
    try {
      binloader_init()
      log('Binloader initialized and running!')
    } catch (e) {
      log('ERROR: Failed to initialize binloader')
      log('Error message: ' + (e as Error).message)
      log('Error name: ' + (e as Error).name)
      if ((e as Error).stack) {
        log('Stack trace: ' + (e as Error).stack)
      }
      throw e
    }
  }

  // تشغيل NetCtrl مع retries لو متفعّل
  if (use_netctrl) {
    log('[loader] Using NetCtrl with retries')
    const ok = run_netctrl_with_retries(3)  // هنا تقدر تغيّر 3 لو حابب
    if (!ok) {
      log('[loader] NetCtrl failed after all retries')
      // هنا نسيب السلوك كما هو (مجرد فشل) عشان ما نغيّرش منطق حساس
    }
  }
} else {
  utils.notify('Already Jailbroken!')
  include('main-menu.js')
}

export function run_binloader () {
  log('Initializing binloader...')
  try {
    binloader_init()
    log('Binloader initialized and running!')
  } catch (e) {
    log('ERROR: Failed to initialize binloader')
    log('Error message: ' + (e as Error).message)
    log('Error name: ' + (e as Error).name)
    if ((e as Error).stack) {
      log('Stack trace: ' + (e as Error).stack)
    }
    throw e
  }
}