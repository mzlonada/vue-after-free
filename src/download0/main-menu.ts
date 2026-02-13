(function () {
  log('Loading minimal main menu...')

  // ????? ??? ???????
  const audio = new jsmaf.AudioClip()
  audio.volume = 0.5
  audio.open('file:///../download0/sfx/bgm.wav')

  // ????? ??????
  jsmaf.root.children.length = 0

  // ???????
  const background = new Image({
    url: 'file:///../download0/img/www.png',
    x: 0,
    y: 0,
    width: 1920,
    height: 1080
  })
  jsmaf.root.children.push(background)

  // ?????? ???? ??????
  const logo = new Image({
    url: 'file:///../download0/img/logo.png',
    x: 960 - 300,
    y: 50,
    width: 600,
    height: 338
  })
  jsmaf.root.children.push(logo)

  // ???????? ?????? ??? ???????
  jsmaf.setTimeout(() => {
    log('Starting loader...')
    include('loader.js')
  }, 2000)

  log('Main menu loaded')
})()