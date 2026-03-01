function show_fail_screen (message) {
  var msg = message || 'Error while checking jailbreak state.\nPlease reboot your PS4 and try again.'

  if (jsmaf && jsmaf.root) {
    jsmaf.root.innerHTML = `
            <div style="color:white;font-size:32px;text-align:center;margin-top:200px;white-space:pre-line;">
                ${msg}
            </div>
        `
  } else {
    console.log(msg)
  }
}
function checkJailbroken () {
  try {
    fn.register(24, 'getuid', [], 'bigint')
    fn.register(23, 'setuid', ['number'], 'bigint')

    var uidBefore = fn.getuid()
    var uidBeforeVal = uidBefore instanceof BigInt ? uidBefore.lo : uidBefore
    log('UID before setuid: ' + uidBeforeVal)

    log('Attempting setuid(0)...')
    try {
      var setuidResult = fn.setuid(0)
      var setuidRet = setuidResult instanceof BigInt ? setuidResult.lo : setuidResult
      log('setuid returned: ' + setuidRet)
    } catch (e) {
      log('setuid threw exception: ' + e.toString())
    }

    var uidAfter = fn.getuid()
    var uidAfterVal = uidAfter instanceof BigInt ? uidAfter.lo : uidAfter
    log('UID after setuid: ' + uidAfterVal)

    var jailbroken = uidAfterVal === 0
    log(jailbroken ? 'Already jailbroken' : 'Not jailbroken')
    log('Exit psvue')
    return jailbroken
  } catch (e) {
    log('checkJailbroken ERROR: ' + e.toString())
    show_fail_screen('Error while checking jailbreak state.\nPlease reboot your PS4 and try again.')
    return false
  }
}
