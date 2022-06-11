if get_option('enable_fuzz')
  unit_test_env = environment()
  if test_env_common_path != []
    unit_test_env.prepend('PATH', test_env_common_path)
  endif

  targets = [
    'core'
  ]
  foreach target : targets
    exe = executable('fuzz_@0@'.format(target), 'fuzz_@0@.c'.format(target),
      c_args: fuzzer_cflags,
      include_directories: [platform_inc, '.'],
      dependencies: [
        rz_util_dep,
        rz_main_dep,
        rz_socket_dep,
        rz_core_dep,
        rz_io_dep,
        rz_bin_dep,
        rz_flag_dep,
        rz_cons_dep,
        rz_asm_dep,
        rz_debug_dep,
        rz_config_dep,
        rz_bp_dep,
        rz_reg_dep,
        rz_syscall_dep,
        rz_type_dep,
        rz_analysis_dep,
        rz_parse_dep,
        rz_egg_dep,
        rz_search_dep,
        rz_hash_dep,
        rz_crypto_dep,
        rz_magic_dep,
        rz_il_dep,
        lrt,
      ],
      install: false,
      install_rpath: rpath_exe,
      implicit_include_directories: false,
      link_args: executable_linkflags
    )
  endforeach
endif
