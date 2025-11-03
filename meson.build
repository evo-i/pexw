project('pexw', 'c',
    version: '2.0',
    default_options: ['c_std=c11'])

executable('pexw', ['pexw.c'])

capstone_dep = dependency('capstone', required: false)

if capstone_dep.found()
  message('Found Capstone library')

  pexw_cross = executable('pexw_cross', ['pexw_cross.c'],
    dependencies: capstone_dep,
    install: true)

  if host_machine.system() == 'linux' or host_machine.system() == 'darwin'
    pexw_cross.add_compile_args(['-Wall', '-Wextra'])
  endif
else
  warning('Capstone not found. Skipping pexw_cross build.')
  message('Install with: apt-get install libcapstone-dev (Linux) or brew install capstone (macOS)')
endif

