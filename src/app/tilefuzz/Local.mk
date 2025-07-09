$(call add-hdrs,driver.h)
$(call add-objs,driver,fd_tilefuzz)
# $(call make-bin,fd_tilefuzz,main,fd_firedancer_dev fd_firedancer fddev_share fdctl_shared fd_disco fd_flamenco fd_ballet fd_tango fd_util firedancer_version)
# fdctl_shared has transitive dependencies on fdctl_platform.  Explicitly
# link against fdctl_platform here to satisfy symbols such as
# fd_file_util_read_all and fd_cap_chk_* that are required by the shared
# library but not provided elsewhere.

$(call make-bin,fd_tilefuzz,main,fd_tilefuzz fd_firedancer_dev fd_firedancer fddev_shared fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util firedancer_version)

$(call make-fuzz-test,fuzz_tiles,fuzz_tiles,fd_tilefuzz fd_firedancer_dev fd_firedancer fddev_shared fdctl_shared fdctl_platform fd_discof fd_disco fd_choreo fd_flamenco fd_funk fd_quic fd_tls fd_reedsol fd_ballet fd_waltz fd_tango fd_util )

