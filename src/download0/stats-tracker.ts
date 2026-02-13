import { fn, mem, BigInt } from 'download0/types'
import { checkJailbroken } from 'download0/check-jailbroken'

// ===============================
//  Statistics Tracker (Stable)
// ===============================

export const stats = {
  total: 0,
  success: 0,

  // ?????? ?????? ???? sandbox
  filepath: '/mnt/sandbox/download/CUSA00960/stats.json',

  // ===============================
  //  Load stats from file
  // ===============================
  load: function () {
    try {
      fn.register(0x3, 'read', ['bigint', 'bigint', 'number'], 'bigint')
      fn.register(0x4, 'write', ['bigint', 'bigint', 'number'], 'bigint')
      fn.register(0x5, 'open', ['string', 'number', 'number'], 'bigint')
      fn.register(0x6, 'close', ['bigint'], 'bigint')

      const fd = fn.open(this.filepath, 0, 0) // O_RDONLY

      if (fd.lt(0)) {
        log('[STATS] No stats file found, starting fresh')
        this.total = 0
        this.success = 0
        return
      }

      const buf = mem.malloc(1024)
      const bytesRead = fn.read(fd, buf, 1024)
      fn.close(fd)

      if (bytesRead.eq(0)) {
        log('[STATS] Empty stats file')
        return
      }

      let str = ''
      for (let i = 0; i < Number(bytesRead); i++) {
        str += String.fromCharCode(mem.view(buf.add(i)).getUint8(0))
      }

      try {
        const parsed = JSON.parse(str)
        this.total = parsed.total || 0
        this.success = parsed.success || 0
        log('[STATS] Loaded: total=' + this.total + ', success=' + this.success)
      } catch (e) {
        log('[STATS] Failed to parse stats file: ' + e)
        this.total = 0
        this.success = 0
      }

    } catch (e) {
      log('[STATS] Error loading stats: ' + e)
      this.total = 0
      this.success = 0
    }
  },

  // ===============================
  //  Save stats to file
  // ===============================
  save: function () {
    try {
      fn.register(0x3, 'read', ['bigint', 'bigint', 'number'], 'bigint')
      fn.register(0x4, 'write', ['bigint', 'bigint', 'number'], 'bigint')
      fn.register(0x5, 'open', ['string', 'number', 'number'], 'bigint')
      fn.register(0x6, 'close', ['bigint'], 'bigint')

      const data = JSON.stringify({
        total: this.total,
        success: this.success
      })

      // O_WRONLY | O_CREAT | O_TRUNC
      const fd = fn.open(this.filepath, 0x601, 0x1FF)

      if (fd.lt(0)) {
        log('[STATS] Failed to open file for writing')
        return false
      }

      const buf = mem.malloc(data.length)
      for (let i = 0; i < data.length; i++) {
        mem.view(buf.add(i)).setUint8(0, data.charCodeAt(i))
      }

      const bytesWritten = fn.write(fd, buf, data.length)
      fn.close(fd)

      if (bytesWritten.eq(data.length)) {
        log('[STATS] Saved: total=' + this.total + ', success=' + this.success)
        return true
      } else {
        log('[STATS] Failed to write all data')
        return false
      }

    } catch (e) {
      log('[STATS] Error saving stats: ' + e)
      return false
    }
  },

  // ===============================
  //  Increment counters
  // ===============================
  incrementTotal: function () {
    this.total++
    log('[STATS] Total incremented to: ' + this.total)
    this.save()
  },

  incrementSuccess: function () {
    this.success++
    log('[STATS] Success incremented to: ' + this.success)
    this.save()
  },

  // ===============================
  //  Get stats
  // ===============================
  get: function () {
    return {
      total: this.total,
      success: this.success,
      failures: this.total - this.success,
      failureRate:
        this.total > 0
          ? ((this.total - this.success) / this.total * 100).toFixed(2) + '%'
          : '0%',
      successRate:
        this.total > 0
          ? (this.success / this.total * 100).toFixed(2) + '%'
          : '0%'
    }
  },

  // ===============================
  //  Print stats
  // ===============================
  print: function () {
    const s = this.get()
    log('[STATS] ====== Statistics ======')
    log('[STATS] Total:        ' + s.total)
    log('[STATS] Success:      ' + s.success)
    log('[STATS] Failures:     ' + s.failures)
    log('[STATS] Success Rate: ' + s.successRate)
    log('[STATS] Failure Rate: ' + s.failureRate)
    log('[STATS] =======================')
  },

  // ===============================
  //  Reset stats
  // ===============================
  reset: function () {
    this.total = 0
    this.success = 0
    log('[STATS] Stats reset')
    this.save()
  }
}