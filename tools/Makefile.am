AM_CPPFLAGS =

LELY_LIBC_LIBS = $(top_builddir)/src/libc/liblely-libc.la
if CODE_COVERAGE_ENABLED
LELY_LIBC_LIBS += $(CODE_COVERAGE_LIBS)
endif

LELY_UTIL_LIBS = $(top_builddir)/src/util/liblely-util.la
LELY_UTIL_LIBS += $(LELY_LIBC_LIBS)

LELY_CAN_LIBS = $(top_builddir)/src/can/liblely-can.la
LELY_CAN_LIBS += $(LELY_UTIL_LIBS)

LELY_CO_LIBS = $(top_builddir)/src/co/liblely-co.la
LELY_CO_LIBS += $(LELY_CAN_LIBS)

LELY_IO_LIBS = $(top_builddir)/src/io/liblely-io.la
LELY_IO_LIBS += $(LELY_CAN_LIBS)

LELY_EV_LIBS = $(top_builddir)/src/ev/liblely-ev.la
LELY_EV_LIBS += $(LELY_UTIL_LIBS)

LELY_IO2_LIBS = $(top_builddir)/src/io2/liblely-io2.la
LELY_IO2_LIBS += $(LELY_EV_LIBS) $(LELY_CAN_LIBS)

bin =
etc =
if !NO_CO_WTM
if PLATFORM_LINUX
bin += can2udp
can2udp_SOURCES = can2udp.c
can2udp_LDADD = $(LELY_IO_LIBS) $(LELY_CO_LIBS)
endif
endif
if !NO_CO_GW_TXT
if !NO_CO_DCF
if !NO_THREADS
if PLATFORM_LINUX
bin += coctl
coctl_SOURCES = coctl.c
coctl_LDADD = $(LELY_IO_LIBS) $(LELY_CO_LIBS)
etc += coctl.dcf
endif
endif
endif
endif
if PLATFORM_LINUX
if !NO_THREADS
bin += cocat
cocat_SOURCES = cocat.c
cocat_LDADD = $(LELY_IO_LIBS) $(LELY_CO_LIBS)
endif
if !NO_CO_TPDO
if !NO_CO_DCF
bin += cocatd
cocatd_SOURCES = cocatd.c
cocatd_LDADD = $(LELY_IO_LIBS) $(LELY_CO_LIBS)
etc += cocatd.dcf
AM_CPPFLAGS += -DCOCATD_DCF="\"$(sysconfdir)/cocatd.dcf\""
endif
endif
endif
if !NO_CO_DCF
if !NO_CO_SDEV
bin += dcf2c
dcf2c_SOURCES = dcf2c.c
if PLATFORM_WIN32
nodist_dcf2c_SOURCES = version.dcf2c.rc
endif
dcf2c_LDADD = $(LELY_CO_LIBS)
endif
endif

bin_PROGRAMS = $(bin)
dist_sysconf_DATA = $(etc)

AM_CPPFLAGS += -I$(top_srcdir)/include
if CODE_COVERAGE_ENABLED
AM_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS)
endif

AM_CFLAGS =
if CODE_COVERAGE_ENABLED
AM_CFLAGS += $(CODE_COVERAGE_CFLAGS)
endif

if PLATFORM_WIN32
.rc.o:
	$(AM_V_GEN) $(LIBTOOL) --silent --tag=RC --mode=compile $(RC) $< -o $@
endif
