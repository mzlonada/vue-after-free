// لو libc_addr مش متعرفة، نحمل userland
if (typeof libc_addr === 'undefined') {
  include('userland.js');
}

// تحميل باقي السكربتات
include('stats-tracker.js');
include('binloader.js');
include('lapse.js');
include('kernel.js');
include('check-jailbroken.js');
include('stats-tracker.js');
log('All scripts loaded');

// تحميل الإحصائيات
stats.load();
function show_success() {
  setTimeout(() => {
    jsmaf.root.children.push(bg_success);
    log('Logging Success...');
    stats.incrementSuccess();
  }, 2000);
}
var audio = new jsmaf.AudioClip();
audio.volume = 0.5;
audio.open('file://../download0/sfx/bgm.wav');
var is_jailbroken = checkJailbroken();

// ===== Helpers =====

function is_exploit_complete() {
  fn.register(24, 'getuid', [], 'bigint');
  fn.register(585, 'is_in_sandbox', [], 'bigint');
  try {
    var uid = fn.getuid();
    var sandbox = fn.is_in_sandbox();
    if (!uid.eq(0) || !sandbox.eq(0)) {
      return false;
    }
  } catch (e) {
    return false;
  }
  return true;
}
function write64(addr, val) {
  mem.view(addr).setBigInt(0, new BigInt(val), true);
}
function read8(addr) {
  return mem.view(addr).getUint8(0);
}
function malloc(size) {
  return mem.malloc(size);
}
function get_fwversion() {
  var buf = malloc(0x8);
  var size = malloc(0x8);
  write64(size, 0x8);
  if (sysctlbyname('kern.sdk_version', buf, size, 0, 0)) {
    var byte1 = Number(read8(buf.add(2)));
    var byte2 = Number(read8(buf.add(3)));
    var version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0');
    return version;
  }
  return null;
}
var FW_VERSION = get_fwversion();
if (FW_VERSION === null) {
  log('ERROR: Failed to determine FW version');
  throw new Error('Failed to determine FW version');
}
var compare_version = (a, b) => {
  var a_arr = a.split('.');
  var amaj = Number(a_arr[0]);
  var amin = Number(a_arr[1]);
  var b_arr = b.split('.');
  var bmaj = Number(b_arr[0]);
  var bmin = Number(b_arr[1]);
  return amaj === bmaj ? amin - bmin : amaj - bmaj;
};

// ===== NetCtrl wrapper مدمج هنا =====

include('netctrl_c0w_twins.js'); // نفس الملف الأصلي

function run_netctrl_once() {
  log('[netctrl_wrapper] starting netctrl_exploit()');
  try {
    netctrl_exploit();
    log('[netctrl_wrapper] netctrl_exploit() returned (no crash)');
    return true;
  } catch (e) {
    log('[netctrl_wrapper] ERROR in netctrl_exploit(): ' + e.message);
    return false;
  }
}
function run_netctrl_with_retries(maxTries) {
  for (var i = 1; i <= maxTries; i++) {
    log('[netctrl_wrapper] Attempt ' + i + '/' + maxTries);
    var ok = run_netctrl_once();
    if (ok) {
      log('[netctrl_wrapper] Success on attempt ' + i);
      return true;
    }
  }
  log('[netctrl_wrapper] All attempts failed');
  return false;
}

// ===== Main logic =====

if (!is_jailbroken) {
  var jb_behavior = typeof CONFIG !== 'undefined' && typeof CONFIG.jb_behavior === 'number' ? CONFIG.jb_behavior : 0;
  stats.incrementTotal();
  utils.notify(FW_VERSION + ' Detected!');
  var use_lapse = false;
  var use_netctrl = false;
  if (jb_behavior === 1) {
    log('JB Behavior: NetControl (forced)');
    use_netctrl = true;
  } else if (jb_behavior === 2) {
    log('JB Behavior: Lapse (forced)');
    use_lapse = true;
  } else {
    log('JB Behavior: Auto Detect');
    if (compare_version(FW_VERSION, '7.00') >= 0 && compare_version(FW_VERSION, '12.02') <= 0) {
      use_lapse = true;
    } else if (compare_version(FW_VERSION, '12.50') >= 0 && compare_version(FW_VERSION, '13.00') <= 0) {
      use_netctrl = true;
    }
  }
  if (use_lapse) {
    log('[loader] Running Lapse exploit...');
    lapse();
    var start_time = Date.now();
    var max_wait_seconds = 5;
    var max_wait_ms = max_wait_seconds * 1000;
    while (!is_exploit_complete()) {
      var elapsed = Date.now() - start_time;
      if (elapsed > max_wait_ms) {
        log('ERROR: Timeout waiting for exploit to complete (' + max_wait_seconds + ' seconds)');
        throw new Error('Lapse timeout');
      }
      var poll_start = Date.now();
      while (Date.now() - poll_start < 500) {}
    }
    show_success();
    var total_wait = ((Date.now() - start_time) / 1000).toFixed(1);
    log('Exploit completed successfully after ' + total_wait + ' seconds');
    log('Initializing binloader...');
    try {
      binloader_init();
      log('Binloader initialized and running!');
    } catch (e) {
      log('ERROR: Failed to initialize binloader');
      log('Error message: ' + e.message);
      log('Error name: ' + e.name);
      if (e.stack) {
        log('Stack trace: ' + e.stack);
      }
      throw e;
    }
  }
  if (use_netctrl) {
    log('[loader] Running NetCtrl exploit with retries...');
    var ok = run_netctrl_with_retries(3);
    if (!ok) {
      log('[loader] NetCtrl failed after all retries');
    }
  }
} else {
  utils.notify('Already Jailbroken!');
  include('main-menu.js');
}
function run_binloader() {
  log('Initializing binloader...');
  try {
    binloader_init();
    log('Binloader initialized and running!');
  } catch (e) {
    log('ERROR: Failed to initialize binloader');
    log('Error message: ' + e.message);
    log('Error name: ' + e.name);
    if (e.stack) {
      log('Stack trace: ' + e.stack);
    }
    throw e;
  }
}