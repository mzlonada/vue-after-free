// تحميل الملفات المطلوبة مسبقًا (Side-effect imports)
import 'download0/languages'
import 'download0/stats-tracker'

import { libc_addr } from 'download0/userland'
import { stats } from 'download0/stats-tracker'
import { lang, useImageText, textImageBase } from 'download0/languages'

;(function () {

  log(lang.loadingConfig)

  // ============================
  //  نظام القراءة والكتابة
  // ============================
  const fs = {
    write(filename: string, content: string, callback: (error: Error | null) => void) {
      const xhr = new jsmaf.XMLHttpRequest()
      xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && callback) {
          callback(xhr.status === 0 || xhr.status === 200 ? null : new Error('failed'))
        }
      }
      xhr.open('POST', 'file://../download0/' + filename, true)
      xhr.send(content)
    },

    read(filename: string, callback: (error: Error | null, data?: string) => void) {
      const xhr = new jsmaf.XMLHttpRequest()
      xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && callback) {
          callback(xhr.status === 0 || xhr.status === 200 ? null : new Error('failed'), xhr.responseText)
        }
      }
      xhr.open('GET', 'file://../download0/' + filename, true)
      xhr.send()
    }
  }

  // ============================
  //  الإعدادات الافتراضية
  // ============================
  const currentConfig = {
    autolapse: false,
    autopoop: false,
    autoclose: false,
    music: true,
    jb_behavior: 0
  }

  let userPayloads: string[] = []
  let configLoaded = false

  const jbBehaviorLabels = [
    lang.jbBehaviorAuto,
    lang.jbBehaviorNetctrl,
    lang.jbBehaviorLapse
  ]

  const jbBehaviorImgKeys = [
    'jbBehaviorAuto',
    'jbBehaviorNetctrl',
    'jbBehaviorLapse'
  ]

  // ============================
  //  UI الأساسي
  // ============================
  jsmaf.root.children.length = 0

  new Style({ name: 'white', color: 'white', size: 24 })
  new Style({ name: 'title', color: 'white', size: 32 })

  if (typeof CONFIG !== 'undefined' && CONFIG.music) {
    const audio = new jsmaf.AudioClip()
    audio.volume = 0.5
    audio.open('file://../download0/sfx/bgm.wav')
  }

  const background = new Image({
    url: 'file:///../download0/img/multiview_bg_VAF.png',
    x: 0, y: 0,
    width: 1920, height: 1080
  })
  jsmaf.root.children.push(background)

  const logo = new Image({
    url: 'file:///../download0/img/logo.png',
    x: 1620, y: 0,
    width: 300, height: 169
  })
  jsmaf.root.children.push(logo)

  if (useImageText) {
    jsmaf.root.children.push(new Image({
      url: textImageBase + 'config.png',
      x: 860, y: 100,
      width: 200, height: 60
    }))
  } else {
    const title = new jsmaf.Text()
    title.text = lang.config
    title.x = 910
    title.y = 120
    title.style = 'title'
    jsmaf.root.children.push(title)
  }

  // ============================
  //  الإحصائيات
  // ============================
  stats.load()
  const statsData = stats.get()

  const statsImgKeys = ['totalAttempts', 'successes', 'failures', 'successRate', 'failureRate']
  const statsValues = [
    statsData.total,
    statsData.success,
    statsData.failures,
    statsData.successRate,
    statsData.failureRate
  ]
  const statsLabels = [
    lang.totalAttempts,
    lang.successes,
    lang.failures,
    lang.successRate,
    lang.failureRate
  ]

  for (let i = 0; i < statsImgKeys.length; i++) {
    const yPos = 120 + (i * 25)

    if (useImageText) {
      jsmaf.root.children.push(new Image({
        url: textImageBase + statsImgKeys[i] + '.png',
        x: 20, y: yPos,
        width: 180, height: 25
      }))

      const valueText = new jsmaf.Text()
      valueText.text = String(statsValues[i])
      valueText.x = 210
      valueText.y = yPos
      valueText.style = 'white'
      jsmaf.root.children.push(valueText)

    } else {
      const lineText = new jsmaf.Text()
      lineText.text = statsLabels[i] + statsValues[i]
      lineText.x = 20
      lineText.y = yPos
      lineText.style = 'white'
      jsmaf.root.children.push(lineText)
    }
  }

  // ============================
  //  خيارات الإعدادات
  // ============================
  const configOptions = [
    { key: 'autolapse', label: lang.autoLapse, imgKey: 'autoLapse', type: 'toggle' },
    { key: 'autopoop', label: lang.autoPoop, imgKey: 'autoPoop', type: 'toggle' },
    { key: 'autoclose', label: lang.autoClose, imgKey: 'autoClose', type: 'toggle' },
    { key: 'music', label: lang.music, imgKey: 'music', type: 'toggle' },
    { key: 'jb_behavior', label: lang.jbBehavior, imgKey: 'jbBehavior', type: 'cycle' }
  ]

  const centerX = 960
  const startY = 300
  const buttonSpacing = 120
  const buttonWidth = 400
  const buttonHeight = 80

  const buttons: Image[] = []
  const buttonTexts: (Image | jsmaf.Text)[] = []
  const buttonMarkers: (Image | null)[] = []
  const buttonOrigPos: { x: number; y: number }[] = []
  const textOrigPos: { x: number; y: number }[] = []
  const valueTexts: (Image | jsmaf.Text)[] = []

  const normalButtonImg = 'file:///assets/img/button_over_9.png'
  const selectedButtonImg = 'file:///assets/img/button_over_9.png'

  for (let i = 0; i < configOptions.length; i++) {
    const opt = configOptions[i]
    const btnX = centerX - buttonWidth / 2
    const btnY = startY + i * buttonSpacing

    const button = new Image({
      url: normalButtonImg,
      x: btnX, y: btnY,
      width: buttonWidth, height: buttonHeight
    })
    buttons.push(button)
    jsmaf.root.children.push(button)

    buttonMarkers.push(null)

    let btnText: Image | jsmaf.Text
    if (useImageText) {
      btnText = new Image({
        url: textImageBase + opt.imgKey + '.png',
        x: btnX + 20, y: btnY + 15,
        width: 200, height: 50
      })
    } else {
      btnText = new jsmaf.Text()
      btnText.text = opt.label
      btnText.x = btnX + 30
      btnText.y = btnY + 28
      btnText.style = 'white'
    }

    buttonTexts.push(btnText)
    jsmaf.root.children.push(btnText)

    if (opt.type === 'toggle') {
      const checkmark = new Image({
        url: currentConfig[opt.key as keyof typeof currentConfig]
          ? 'file:///assets/img/check_small_on.png'
          : 'file:///assets/img/check_small_off.png',
        x: btnX + 320, y: btnY + 20,
        width: 40, height: 40
      })
      valueTexts.push(checkmark)
      jsmaf.root.children.push(checkmark)

    } else {
      let valueLabel: Image | jsmaf.Text
      if (useImageText) {
        valueLabel = new Image({
          url: textImageBase + jbBehaviorImgKeys[currentConfig.jb_behavior] + '.png',
          x: btnX + 230, y: btnY + 15,
          width: 150, height: 50
        })
      } else {
        valueLabel = new jsmaf.Text()
        valueLabel.text = jbBehaviorLabels[currentConfig.jb_behavior]
        valueLabel.x = btnX + 250
        valueLabel.y = btnY + 28
        valueLabel.style = 'white'
      }
      valueTexts.push(valueLabel)
      jsmaf.root.children.push(valueLabel)
    }

    buttonOrigPos.push({ x: btnX, y: btnY })
    textOrigPos.push({ x: btnText.x, y: btnText.y })
  }

  // ============================
  //  زر الرجوع
  // ============================
  const backX = centerX - buttonWidth / 2
  const backY = startY + configOptions.length * buttonSpacing + 100

  const backButton = new Image({
    url: normalButtonImg,
    x: backX, y: backY,
    width: buttonWidth, height: buttonHeight
  })
  buttons.push(backButton)
  jsmaf.root.children.push(backButton)

  const backMarker = new Image({
    url: 'file:///assets/img/ad_pod_marker.png',
    x: backX + buttonWidth - 50,
    y: backY + 35,
    width: 12, height: 12,
    visible: false
  })
  buttonMarkers.push(backMarker)
  jsmaf.root.children.push(backMarker)

  let backText: Image | jsmaf.Text
  if (useImageText) {
    backText = new Image({
      url: textImageBase + 'back.png',
      x: backX + 20, y: backY + 15,
      width: 200, height: 50
    })
  } else {
    backText = new jsmaf.Text()
    backText.text = lang.back
    backText.x = backX + buttonWidth / 2 - 20
    backText.y = backY + buttonHeight / 2 - 12
    backText.style = 'white'
  }
  buttonTexts.push(backText)
  jsmaf.root.children.push(backText)

  buttonOrigPos.push({ x: backX, y: backY })
  textOrigPos.push({ x: backText.x, y: backText.y })

  // ============================
  //  الأنيميشن + التنقل
  // ============================
  let zoomInInterval: number | null = null
  let zoomOutInterval: number | null = null
  let prevButton = -1
  let currentButton = 0

  function easeInOut(t: number) {
    return (1 - Math.cos(t * Math.PI)) / 2
  }

  function animateZoomIn(btn: Image, text: Image | jsmaf.Text, ox: number, oy: number, tx: number, ty: number) {
    if (zoomInInterval) jsmaf.clearInterval(zoomInInterval)
    const startScale = btn.scaleX || 1.0
    const endScale = 1.1
    const duration = 175
    let elapsed = 0
    const step = 16

    zoomInInterval = jsmaf.setInterval(() => {
      elapsed += step
      const t = Math.min(elapsed / duration, 1)
      const eased = easeInOut(t)
      const scale = startScale + (endScale - startScale) * eased

      btn.scaleX = scale
      btn.scaleY = scale
      btn.x = ox - (buttonWidth * (scale - 1)) / 2
      btn.y = oy - (buttonHeight * (scale - 1)) / 2

      text.scaleX = scale
      text.scaleY = scale
      text.x = tx - (buttonWidth * (scale - 1)) / 2
      text.y = ty - (buttonHeight * (scale - 1)) / 2

      if (t >= 1) {
        jsmaf.clearInterval(zoomInInterval!)
        zoomInInterval = null
      }
    }, step)
  }

  function animateZoomOut(btn: Image, text: Image | jsmaf.Text, ox: number, oy: number, tx: number, ty: number) {
    if (zoomOutInterval) jsmaf.clearInterval(zoomOutInterval)
    const startScale = btn.scaleX || 1.1
    const endScale = 1.0
    const duration = 175
    let elapsed = 0
    const step = 16

    zoomOutInterval = jsmaf.setInterval(() => {
      elapsed += step
      const t = Math.min(elapsed / duration, 1)
      const eased = easeInOut(t)
      const scale = startScale + (endScale - startScale) * eased

      btn.scaleX = scale
      btn.scaleY = scale
      btn.x = ox - (buttonWidth * (scale - 1)) / 2
      btn.y = oy - (buttonHeight * (scale - 1)) / 2

      text.scaleX = scale
      text.scaleY = scale
      text.x = tx - (buttonWidth * (scale - 1)) / 2
      text.y = ty - (buttonHeight * (scale - 1)) / 2

      if (t >= 1) {
        jsmaf.clearInterval(zoomOutInterval!)
        zoomOutInterval = null
      }
    }, step)
  }

  function updateHighlight() {
    const prev = prevButton
    const curr = currentButton

    if (prev >= 0 && prev !== curr) {
      const btn = buttons[prev]
      const txt = buttonTexts[prev]
      const marker = buttonMarkers[prev]

      btn.url = normalButtonImg
      btn.alpha = 0.7
      btn.borderColor = 'transparent'
      btn.borderWidth = 0
      if (marker) marker.visible = false

      animateZoomOut(btn, txt, buttonOrigPos[prev].x, buttonOrigPos[prev].y, textOrigPos[prev].x, textOrigPos[prev].y)
    }

    for (let i = 0; i < buttons.length; i++) {
      const btn = buttons[i]
      const txt = buttonTexts[i]
      const marker = buttonMarkers[i]
      const ox = buttonOrigPos[i].x
      const oy = buttonOrigPos[i].y
      const tx = textOrigPos[i].x
      const ty = textOrigPos[i].y

      if (i === curr) {
        btn.url = selectedButtonImg
        btn.alpha = 1.0
        btn.borderColor = 'rgb(100,180,255)'
        btn.borderWidth = 3
        if (marker) marker.visible = true
        animateZoomIn(btn, txt, ox, oy, tx, ty)
      } else if (i !== prev) {
        btn.url = normalButtonImg
        btn.alpha = 0.7
        btn.borderColor = 'transparent'
        btn.borderWidth = 0
        btn.scaleX = 1.0
        btn.scaleY = 1.0
        btn.x = ox
        btn.y = oy
        txt.scaleX = 1.0
        txt.scaleY = 1.0
        txt.x = tx
        txt.y = ty
        if (marker) marker.visible = false
      }
    }

    prevButton = curr
  }

  function updateValueText(index: number) {
    const opt = configOptions[index]
    const valueText = valueTexts[index]
    if (!opt || !valueText) return

    if (opt.type === 'toggle') {
      const value = currentConfig[opt.key as keyof typeof currentConfig]
      ;(valueText as Image).url = value
        ? 'file:///assets/img/check_small_on.png'
        : 'file:///assets/img/check_small_off.png'
    } else {
      if (useImageText) {
        ;(valueText as Image).url =
          textImageBase + jbBehaviorImgKeys[currentConfig.jb_behavior] + '.png'
      } else {
        ;(valueText as jsmaf.Text).text =
          jbBehaviorLabels[currentConfig.jb_behavior]
      }
    }
  }

  function saveConfig() {
    if (!configLoaded) {
      log('Config not loaded yet, skipping save')
      return
    }

    let configContent = 'const CONFIG = {\n'
    configContent += `    autolapse: ${currentConfig.autolapse},\n`
    configContent += `    autopoop: ${currentConfig.autopoop},\n`
    configContent += `    autoclose: ${currentConfig.autoclose},\n`
    configContent += `    music: ${currentConfig.music},\n`
    configContent += `    jb_behavior: ${currentConfig.jb_behavior}\n`
    configContent += '};\n\n'

    configContent += 'const payloads = [\n'
    for (let i = 0; i < userPayloads.length; i++) {
      configContent += `    "${userPayloads[i]}"`
      if (i < userPayloads.length - 1) configContent += ','
      configContent += '\n'
    }
    configContent += '];\n'

        fs.write('config.js', configContent, err => {
      if (err) {
        log('ERROR: Failed to save config: ' + err.message)
      } else {
        log('Config saved successfully')
      }
    })
  }

  function loadConfig() {
    fs.read('config.js', (err: Error | null, data?: string) => {
      if (err) {
        log('ERROR: Failed to read config: ' + err.message)
        configLoaded = true
        return
      }

      try {
        // eslint-disable-next-line no-eval
        eval(data || '') // تحميل CONFIG و payloads من الملف

        if (typeof CONFIG !== 'undefined') {
          currentConfig.autolapse = CONFIG.autolapse || false
          currentConfig.autopoop = CONFIG.autopoop || false
          currentConfig.autoclose = CONFIG.autoclose || false
          currentConfig.music = CONFIG.music !== false
          currentConfig.jb_behavior = CONFIG.jb_behavior || 0
        }

        if (typeof payloads !== 'undefined' && Array.isArray(payloads)) {
          userPayloads = payloads.slice()
        }

        for (let i = 0; i < configOptions.length; i++) {
          updateValueText(i)
        }

        configLoaded = true
        log('Config loaded successfully')

      } catch (e) {
        log('ERROR: Failed to parse config: ' + (e as Error).message)
        configLoaded = true
      }
    })
  }
})();