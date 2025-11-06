project('pexw', 'c',
    version: '2.0',
    default_options: [
      'c_std=c17',
      'warning_level=3',
      'buildtype=release'])

threads_dep = dependency('threads')

executable('pexw', ['pexw.c'],
           dependencies: [threads_dep])
