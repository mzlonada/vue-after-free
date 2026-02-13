import 'download0/languages'
import { lang, useImageText, textImageBase } from 'download0/languages'



;(function () {

  log(lang.loadingMainMenu)

  jsmaf.root.children.length = 0

  // الخلفية
  const background = new Image({
    url: 'file:///../download0/img/background.png',
    x: 0, y: 0,
    width: 1920, height: 1080
  })
  jsmaf.root.children.push(background)

  // اللوجو
  const logo = new Image({
    url: 'file:///../download0/img/logo.png',
    x: 660, y: 80,
    width: 600, height: 338
  })
  jsmaf.root.children.push(logo)

  // رسالة بسيطة
  const loadingText = new jsmaf.Text()
  loadingText.text = lang.loadingMainMenu
  loadingText.x = 1920 / 2 - 200
  loadingText.y = 900
  loadingText.style = 'white'
  jsmaf.root.children.push(loadingText)

  // بعد ثانية → شغّل الإكسبلويت تلقائيًا
  jsmaf.setTimeout(() => {
    try {
      log('Auto‑loading loader.js...')
      include('loader.js')
    } catch (e) {
      log('ERROR loading loader.js: ' + (e as Error).message)
    }
  }, 1000)

  log(lang.mainMenuLoaded)
})()