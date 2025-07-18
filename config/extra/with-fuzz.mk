include config/extra/with-handholding.mk

FD_HAS_FUZZ:=1
CPPFLAGS+=-DFD_HAS_FUZZ=1

CPPFLAGS+=-fno-omit-frame-pointer
CPPFLAGS+=-fsanitize=fuzzer-no-link
CPPFLAGS+=-fsanitize-coverage=inline-8bit-counters

CFLAGS+=-ggdb3
CXXFLAGS+=-ggdb3


LDFLAGS+=-fsanitize-coverage=inline-8bit-counters
LDFLAGS_FUZZ+=-fsanitize=fuzzer
