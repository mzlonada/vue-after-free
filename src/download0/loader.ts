import { libc_addr } from 'download0/userland'
import { stats } from 'download0/stats-tracker'
import { fn, mem, BigInt, utils } from 'download0/types'
import { sysctlbyname } from 'download0/kernel'
import { lapse } from 'download0/lapse'
import { binloader_init } from 'download0/binloader'
import { checkJailbroken } from 'download0/check-jailbroken'

// تحميل userland لو مش موجود
if (typeof libc_addr === 'undefined') {
  include('download0/userland.js')
}

// تحميل السكربتات
include('download0/stats-tracker.js')
include('download0/binloader.js')
include('download0/lapse.js')
include('download0/kernel.js')
include('download0/check-jailbroken.js')
include('download0/netctrl_c0w_twins.js')

log('All scripts loaded')

// تحميل الإحصائيات
stats.load()

// ربط UI المينيو الجديد
declare const showSuccess: (() => void) | undefined
declare const showFail: (() => void) | undefined

// ===== Helpers =====

function is_exploit_complete () {
  fn.register(24, 'getuid', [], 'bigint')
  fn.register(585, 'is_in_sandbox', [], 'bigint')
  try {
    const uid = fn.getuid()
    const sandbox = fn.is_in_sandbox()
    if (!uid.eq(0) || !sandbox.eq(0)) return false
  } catch {
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
    const byte1 = Number(read8(buf.add(2)))
    const byte2 = Number(read8(buf.add(3)))
    return byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0')
  }
  return null
}

const FW_VERSION = get_fwversion()
if (FW_VERSION === null) {
  log('ERROR: Failed to determine FW version')
  throw new Error('Failed to determine FW version')
}

const compare_version = (a: string, b: string) => {
  const aa = a.split('.')
  const bb = b.split('.')
  const amaj = Number(aa[0])
  const amin = Number(aa[1])
  const bmaj = Number(bb[0])
  const bmin = Number(bb[1])
  return amaj === bmaj ? amin - bmin : amaj - bmaj
}

// ===== NetCtrl wrapper =====

function run_netctrl_once (): boolean {
  log('[netctrl_wrapper] starting netctrl_exploit()')
  try {
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

// ===== Main logic =====

const is_jailbroken = checkJailbroken()

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
    log('[loader] Running Lapse exploit...')
    lapse()

    const start = Date.now()
    const timeout = 5000

    while (!is_exploit_complete()) {
      if (Date.now() - start > timeout) {
        log('ERROR: Lapse timeout')
        if (typeof showFail === 'function') showFail()
        throw new Error('Lapse timeout')
      }
    }

    if (typeof showSuccess === 'function') showSuccess()
    log('Lapse exploit completed successfully')

    try {
      binloader_init()
      log('Binloader initialized!')
    } catch (e) {
      log('ERROR: Failed to initialize binloader')
      throw e
    }
  }

  // ===== NetCtrl =====
  if (use_netctrl) {
    log('[loader] Running NetCtrl exploit with retries...')
    const ok = run_netctrl_with_retries(3)

    if (ok) {
      log('[loader] NetCtrl exploit completed successfully')
      if (typeof showSuccess === 'function') showSuccess()
      // binloader_init() لو عايز تشغله بعد النجاح
    } else {
      log('[loader] NetCtrl failed after all retries')
      if (typeof showFail === 'function') showFail()
      utils.notify('NetCtrl failed - reboot and try again')
    }
  }

} else {
  utils.notify('Already Jailbroken!')
  include('download0/main-menu.js')
}

// ===== Binloader manual run =====
export function run_binloader () {
  try {
    binloader_init()
    log('Binloader initialized and running!')
  } catch (e) {
    log('ERROR: Failed to initialize binloader')
    throw e
  }
}