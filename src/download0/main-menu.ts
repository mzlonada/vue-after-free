import 'download0/languages'
import { lang } from 'download0/languages'
import { fn, BigInt, mem } from 'download0/types'

;(function () {

  log(lang.loadingMainMenu)

  jsmaf.root.children.length = 0

  const background = new Image({
    url: 'file:///../download0/img/background.png',
    x: 0, y: 0,
    width: 1920, height: 1080
  })
  jsmaf.root.children.push(background)

  const successImg = new Image({
    url: 'file:///../download0/img/success_full.png',
    x: 0, y: 0,
    width: 1920, height: 1080,
    visible: false
  })
  jsmaf.root.children.push(successImg)

  const failImg = new Image({
    url: 'file:///../download0/img/fail_full.png',
    x: 0, y: 0,
    width: 1920, height: 1080,
    visible: false
  })
  jsmaf.root.children.push(failImg)

  ;(window as any).showSuccess = () => {
    successImg.visible = true
    failImg.visible = false
  }

  ;(window as any).showFail = () => {
    failImg.visible = true
    successImg.visible = false
  }

  log(lang.mainMenuLoaded)
})()