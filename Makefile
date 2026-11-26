CC     = gcc
AR     = ar rcs
RM     = rm -rf
MKDIR  = mkdir -p
CP     = cp
MV     = mv
LN     = ln -s

#name of executable file to generate
OUTPUT   = security

#directory where probe will be installed on
ifndef MMT_BASE
  MMT_BASE             := /opt/mmt
  NEED_ROOT_PERMISSION := 1
else
  $(info INFO: Set default folder of MMT to $(MMT_BASE))
endif

INSTALL_DIR := $(MMT_BASE)/security
MMT_DPI_DIR := $(MMT_BASE)/dpi

# directory where MMT-DPI was installed


#get git version abbrev; "nogit" when the tree has no git metadata that git can
# read (a tarball, or a mount whose ownership git refuses), so a package built
# there still gets a clear version part (fork #47)
GIT_VERSION := $(shell git log --format="%h" -n 1 2>/dev/null)
ifeq ($(GIT_VERSION),)
  GIT_VERSION := nogit
endif
VERSION     := 1.2.22
# minimum MMT-DPI version required by the deb and rpm packages (readme.md):
# the latest release, the one CI tests (DPI_VERSION in .github/workflows/c-cpp.yml)
MIN_DPI_VERSION := 1.10.3

CACHE_LINESIZE := 64 #$(shell getconf LEVEL1_DCACHE_LINESIZE)

#set of library
LIBS     += -ldl -lpthread -lxml2   # -l:libmmt_http2.so

CFLAGS   += -fPIC -Wall -DINSTALL_DIR=\"$(INSTALL_DIR)\" -DVERSION_NUMBER=\"$(VERSION)\" -DGIT_VERSION=\"$(GIT_VERSION)\" -DLEVEL1_DCACHE_LINESIZE=$(CACHE_LINESIZE) -Wno-unused-variable -Wno-unused-function -Wuninitialized -I/usr/include/libxml2/  -I$(MMT_DPI_DIR)/include    #-I/usr/include/nghttp2 -lnghttp2
CLDFLAGS += -I$(MMT_DPI_DIR)/include -L$(MMT_DPI_DIR)/lib -L/usr/local/lib #-I/usr/include/nghttp2 -lnghttp2

#a specific flag for each .o file
CFLAGS += $(CFLAGS-$@)

#for debuging
ifdef DEBUG
  CFLAGS   += -g -DDEBUG_MODE -O0 -fstack-protector-all
else
  CFLAGS   += -O3
endif

ifdef VALGRIND
  CFLAGS += -DVALGRIND_MODE
endif

# AddressSanitizer build of the engine, the library and the rules:
# `make ASAN=1`. The only exception is compile_rule, the build-time rule
# generator: it is kept uninstrumented (see its target below), otherwise
# LeakSanitizer would fail it at exit and no rule could be compiled.
ifdef ASAN
  CFLAGS        += -fsanitize=address -g
  CLDFLAGS      += -fsanitize=address
  RULE_GCC_ARGS := -fsanitize=address
  LIBS          += -l:libmmt_core.so
endif

ifdef TSAN
  CFLAGS        += -fsanitize=thread
  CLDFLAGS      += -fsanitize=thread
  RULE_GCC_ARGS := -fsanitize=thread
  # -fsanitize=thread links a PIE, which resolves the undefined references of
  # libmmt_tcpip.so: it needs libmmt_core in the link (standalone already has it)
  LIBS          += -l:libmmt_core.so
endif

# UndefinedBehaviorSanitizer build of the engine, the library and the rules:
# `make UBSAN=1` (or combined with ASAN: `make ASAN=1 UBSAN=1`). Like ASAN and
# TSAN, compile_rule stays uninstrumented (see its target below).
ifdef UBSAN
  CFLAGS        += -fsanitize=undefined -g
  CLDFLAGS      += -fsanitize=undefined
  RULE_GCC_ARGS += -fsanitize=undefined
endif

ifdef REDIS
  CFLAGS += -DMODULE_REDIS_OUTPUT
  LIBS   += -lhiredis
  $(info => Enable: Output to redis)	
endif

#Enable update_rules if this parameter is different 0 
ifndef UPDATE_RULES 
else
  ifneq "$(UPDATE_RULES)" "0"
  		CFLAGS += -DMODULE_ADD_OR_RM_RULES_RUNTIME
  endif
endif

# Build-flavor stamp (fork #54): the object rules carry no mark of the flag
# set they were compiled with, so `make ASAN=1` on a tree last built plain
# (or the reverse) reused the old objects and linked a partly instrumented
# binary. The expanded flag set is recorded in $(FLAVOR_STAMP); when it
# changes the stamp is rewritten - newer than every object - and make
# rebuilds them all. An unchanged flavor costs nothing: the objects are
# newer than the stamp and stay up to date.
# The write happens here, while the makefile is read, only when the content
# differs, and never under -n/-t/-q, where no command runs and a new stamp
# would lie about the objects' flavor.
# $(file ...) exists only since GNU make 4.0, and its $(file <...) read
# operator only since 4.1: on make 3.x it expands to nothing, so the
# stamp would never be written and the flavor bug would persist
# silently, and on exactly 4.0 the read below dies with make's own
# cryptic "Invalid file operation: <". Fail loudly instead.
$(if $(filter 3.% 4.0,$(MAKE_VERSION)),$(error .build-flavor stamp needs GNU make >= 4.1 ($(MAKE_VERSION) found)))
FLAVOR_STAMP := .build-flavor
# GIT_VERSION is filtered out: it changes with every commit and a new HEAD
# alone must not rebuild the tree (and never did). The signature is
# normalized once with $(strip): the content read back from the stamp file
# is in $(strip) form too, while an un-stripped signature keeps whitespace
# runs (the padding before the '#' comments of LIBS and CLDFLAGS, the '+='
# joins) that would never match and would rewrite the stamp on every
# parse.
# CFLAGS-$(@) per-target additions and CFLAG-PLUGINS-ENGINE (the
# STATIC_RULES_SUFFIX_LIST accumulated while the rule objects compile) are
# not part of the signature: no CFLAGS-* variable is defined today and the
# suffix list is derived from the same rules/*.xml set.
# The DPI installed under $(MMT_DPI_DIR) is a build input of every object:
# its include/ is on the compile line and the generated src/dpi/mmt_dpi.h
# supplies the attribute ids the rules embed. An upgrade in place - a
# package swapped at the same prefix - leaves the flag set and the
# directory mtime unchanged, so nothing below saw it: the objects stayed
# and every rules/*.so kept the previous DPI's ids (fork #70, review M2).
# Hashing the installed files into the signature makes a swap rewrite the
# stamp while the makefile is read, so the objects rebuild in the same
# make - the header file itself cannot be the normal prerequisite here:
# its recipe below runs on every make and a dry run would count that as
# remade, planning the whole tree every time. The order-only prerequisite
# of %.o/%.gen.o is kept instead: it guarantees the regen check runs
# before any compile.
# The stamp matters only to goals that compile objects (an empty
# MAKECMDGOALS is the default goal `all`); the clean and uninstall goals
# get no stray write - `clean` deletes the stamp right away anyway. The
# same filter gates the DPI hash: those goals compile nothing, so hashing
# the installed tree there is wasted work on every parse (fork #70,
# review L7).
FLAVOR_GOALS := $(if $(MAKECMDGOALS),$(filter-out clean clean-all clean-rules dist-clean uninstall,$(MAKECMDGOALS)),all)
# `find -L` keeps a symlinked $(MMT_DPI_DIR) - a versioned prefix managed
# as `dpi -> dpi-x.y.z` - inside the signature: without it find lists the
# link itself, the hash is the md5 of empty input and no in-place swap is
# ever seen (fork #70, review M3). The cut drops md5sum's ` -` stdin tag
# (review L7).
DPI_SIG := $(if $(FLAVOR_GOALS),$(shell find -L '$(MMT_DPI_DIR)' -type f -print0 2>/dev/null | sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | cut -d' ' -f1))
FLAVOR_SIG := $(strip $(DPI_SIG)|$(CC)|$(AR)|STATIC_LINK=$(STATIC_LINK)|$(filter-out -DGIT_VERSION=%,$(CFLAGS))|$(CLDFLAGS)|$(RULE_GCC_ARGS)|$(LIBS))
# -n/-t/-q come bundled as letters in the first MAKEFLAGS word
FLAVOR_FLAGS := $(filter-out --%,$(firstword $(MAKEFLAGS)))
ifneq ($(FLAVOR_GOALS),)
ifneq ($(strip $(file <$(FLAVOR_STAMP))),$(FLAVOR_SIG))
  # nothing is written under -n/-t/-q, so a dry run right after a DPI
  # swap shows none of the rebuild the real run then does (fork #70,
  # review L6)
  ifeq ($(findstring n,$(FLAVOR_FLAGS))$(findstring t,$(FLAVOR_FLAGS))$(findstring q,$(FLAVOR_FLAGS)),)
    $(file >$(FLAVOR_STAMP),$(FLAVOR_SIG))
  endif
endif
endif
# FLAVOR_DEP rides inside the object and rule recipes' prerequisite lists
# when the stamp exists; an explicit `x.o: $(FLAVOR_DEP)` rule instead would
# exempt the absolute-path objects from implicit rules (they would be
# "remade" without ever compiling).
FLAVOR_DEP := $(wildcard $(FLAVOR_STAMP))
# The stamp needs a rule of its own: a pattern-rule prerequisite that does
# not exist yet (the stamp was just written above, so make has not seen it)
# and cannot be made disqualifies the whole pattern rule - `%.o` would
# silently fall back to the built-in rule and `rules/%.so` would fail with
# "No rule to make target" on the first build of a fresh tree. The `;` ends
# an empty recipe: it makes the stamp "makable" without ever running or
# printing anything, so `make -nB` still prints exactly the lines it did
# before.
$(FLAVOR_STAMP): ;

#folders containing source files
SRCDIR := $(abspath ./src )

#objects to generate
LIB_OBJS  :=  $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/lib/*.c))
TEST_OBJS :=  $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/../test/*.c))

#filter out 2 files: src/main.c and src/test_probe.c
MAIN_SRCS := $(wildcard   $(SRCDIR)/*.c)
MAIN_SRCS := $(filter-out $(SRCDIR)/tips.c, $(MAIN_SRCS))

MAIN_SRCS := $(filter-out $(SRCDIR)/main_dpi.c, $(MAIN_SRCS))
MAIN_OBJS := $(patsubst %.c,%.o, $(MAIN_SRCS))

MMT_DPI_HEADER := $(SRCDIR)/dpi/mmt_dpi.h

ifndef VERBOSE
  QUIET := @
endif

MAIN_DPI = gen_dpi_header

MAIN_GEN_PLUGIN = compile_rule

MAIN_PLUGIN_INFO = rule_info

MAIN_STAND_ALONE = mmt_sec_standalone

MAIN_SEC_SERVER = mmt_sec_server

LIB_NAME = libmmt_security2


all: $(MMT_DPI_HEADER) compile_rule rule_info sec_server lib standalone

#this is useful when running the tools, such as, gen_dpi, compile_rule
# but libmmt_core, ... are not found by ldd
export LD_LIBRARY_PATH=$(MMT_DPI_DIR)/lib

# check if there exists the folder of MMT-DPI 
$(MMT_DPI_DIR):
	@echo "ERROR: Not found MMT-DPI at folder $(MMT_DPI_DIR).\n"
	@exit 1
	
# always-out-of-date prerequisite: it lets the header recipe below run on
# every make, so the header tracks the installed DPI instead of file mtimes
# (fork #70)
.PHONY: FORCE
FORCE:

#The generator is a real target: its source is a prerequisite, so editing
# main_gen_dpi.c relinks the binary (fork #70)
$(MAIN_DPI): $(SRCDIR)/main_gen_dpi.c | $(MMT_DPI_DIR)
	$(QUIET) $(CC) -I$(MMT_DPI_DIR)/include -L$(MMT_DPI_DIR)/lib -o $(MAIN_DPI) $(SRCDIR)/main_gen_dpi.c -l:libmmt_core.so -ldl

#Generate a DPI header, so mmt-security does not depend on mmt-dpi after having the header.
# The header is tracked so it is readable without mmt-dpi, but when
# $(MMT_DPI_DIR) exists the installed DPI is authoritative (fork #70):
# regenerate into a temp file on every make and replace the tracked copy
# only when the content differs - the first two lines (a timestamp and the
# generator's own path) are volatile and skipped by the compare, so a
# settled tree is a no-op and nothing rebuilds needlessly. A prerequisite
# on $(MMT_DPI_DIR) alone could not do this: on a fresh clone the tracked
# header is always newer than the install dir, so the stale copy always won.
gen_dpi $(MMT_DPI_HEADER): $(MAIN_DPI) $(MMT_DPI_DIR) FORCE
	$(QUIET) set -e; T="$(MMT_DPI_HEADER).new"; \
		./$(MAIN_DPI) "$$T"; \
		sed '1,2d' "$$T" > "$$T.n"; \
		if [ -f "$(MMT_DPI_HEADER)" ]; then \
			sed '1,2d' "$(MMT_DPI_HEADER)" > "$$T.o"; \
		else \
			: > "$$T.o"; \
		fi; \
		if cmp -s "$$T.n" "$$T.o"; then \
			rm -f "$$T" "$$T.n" "$$T.o"; \
		else \
			echo ">>> Generate list of protocols and their attributes to $(MMT_DPI_HEADER)"; \
			mv "$$T" "$(MMT_DPI_HEADER)"; \
			rm -f "$$T.n" "$$T.o"; \
		fi

# The header is order-only: it orders the regen check before this compile.
# A *changed* header invalidates objects through $(FLAVOR_DEP) - the DPI
# content is hashed into FLAVOR_SIG (fork #70, review M2)
%.o: %.c $(FLAVOR_DEP) | $(MMT_DPI_HEADER)
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -c -o $@ $<
	
test.%: $(MMT_DPI_HEADER) $(LIB_OBJS) test/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $@ $(CLDFLAGS)  $^ $(LIBS)

perf.%: $(LIB_OBJS) test/perf/%.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $@ $(CLDFLAGS)  $^ $(LIBS)

# Objects that compile_rule is linked from. compile_rule is a host-side code
# generator that runs inside the build; it exits while a few small
# allocations are still live, so an ASan build of it is failed by
# LeakSanitizer at the first rules/%.so recipe, and `make ASAN=1` could not
# build the rules from a clean tree. A TSan build has the same problem:
# where the TSan runtime cannot start (e.g. aarch64: "unexpected memory
# mapping"), an instrumented compile_rule aborts and no rule is generated.
# Under ASAN or TSAN it is therefore compiled and linked without the
# sanitizer flags, from a separate set of objects (*.gen.o) - the engine,
# the library and the rule plugins keep them.
# In a default build it links the normal objects, as before.
ifneq ($(strip $(ASAN) $(TSAN) $(UBSAN)),)
  GEN_CFLAGS   := $(filter-out -fsanitize=address -fsanitize=thread -fsanitize=undefined,$(CFLAGS))
  GEN_CLDFLAGS := $(filter-out -fsanitize=address -fsanitize=thread -fsanitize=undefined,$(CLDFLAGS))
  GEN_OBJS     := $(patsubst %.o,%.gen.o,$(LIB_OBJS) $(SRCDIR)/main_gen_plugin.o)
else
  GEN_CLDFLAGS := $(CLDFLAGS)
  GEN_OBJS     := $(LIB_OBJS) $(SRCDIR)/main_gen_plugin.o
endif

# same as %.o above: the header orders the regen check, the stamp carries
# the invalidation (fork #70, review M2)
%.gen.o: %.c $(FLAVOR_DEP) | $(MMT_DPI_HEADER)
	@echo "[COMPILE] $(notdir $@)"
	$(QUIET) $(CC) $(GEN_CFLAGS) $(GEN_CLDFLAGS) -c -o $@ $<

compile_rule: $(GEN_OBJS)
	@echo "[COMPILE] $(MAIN_GEN_PLUGIN)"
	$(QUIET) $(CC) -o $(MAIN_GEN_PLUGIN) $(GEN_CLDFLAGS) $^ $(LIBS) 
	
sec_server: $(LIB_OBJS)  $(SRCDIR)/main_sec_server.o
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_SEC_SERVER)  $(CFLAGS)  $(CLDFLAGS) $^ $(LIBS)
	
standalone:  $(MMT_DPI_DIR) $(LIB_OBJS)  $(SRCDIR)/main_sec_standalone.o $(RULE_OBJS) --refresh-plugin-engine
	@echo "[COMPILE] $@"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_STAND_ALONE) $(CLDFLAGS) $(LIB_OBJS)  $(RULE_OBJS)  $(SRCDIR)/main_sec_standalone.o $(LIBS) -lpcap  -l:libmmt_core.so 

rule_info: $(LIB_OBJS) $(SRCDIR)/main_plugin_info.o
	@echo "[COMPILE] $(MAIN_PLUGIN_INFO)"
	$(QUIET) $(CC) -Wl,--export-dynamic -o $(MAIN_PLUGIN_INFO) $(CLDFLAGS) $^ $(LIBS)


RULE_XML := $(sort $(wildcard rules/*.xml))

ifdef STATIC_LINK
#this block is for statically linking rules into libmmt_security.a

#here we got a list of rule files
RULE_OBJS := $(patsubst %.xml,%.o, $(RULE_XML))

#Generate code C of a rule; the .xml is a prerequisite for the same
# reason as in rules/%.so below (fork #70)
rules/%.c: rules/%.xml compile_rule
	$(QUIET) echo [COMPILE] rules/$*.xml
	$(QUIET) ./$(MAIN_GEN_PLUGIN) $@ rules/$*.xml -c > /dev/null 2>&1

#Compile code C of a rule and add a RULE_SUFFIX is the name of the rule
# (we replace the non-alphanumeric characters by underscores)
rules/%.o: rules/%.c $(FLAVOR_DEP)
	@#replace non-alphanumeric characters in the file name of rule(s) by underscores
	$(eval RULE_SUFFIX=$(shell echo $* | sed "s/[^[:alnum:]]/_/g"))
	
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) -I./src/lib -I./src/dpi -c -o $@ $< -DRULE_SUFFIX=_$(RULE_SUFFIX)
	@#we do not need its C code any more, delete it
	$(QUIET) $(RM) $<
	@#remember the list of suffix of compiled rules
	$(eval STATIC_RULES_SUFFIX_LIST += SUFFIX($(RULE_SUFFIX)))


#update the CFLAG for plugins_engine.so
CFLAG-PLUGINS-ENGINE +=  -DSTATIC_RULES_SUFFIX_LIST="$(STATIC_RULES_SUFFIX_LIST)"
  
SAMPLE_RULES :=
else
  SAMPLE_RULES := $(patsubst %.xml,%.so, $(RULE_XML))
  RULE_OBJS    :=
endif

# This target is to deal with the issue when user uses 
#   2 differrent values of INSTALL_DIR for "make" and "make install"
# Ex: make; sudo make install INSTALL_DIR=/tmp/mmt/security
#   - the first "make" will set in the codes MMT_SEC_PLUGINS_REPOSITORY_OPT to /opt/mmt/security/rules
#   - while the second "make install" will install to /tmp/mmt
# Thus we need to recompile the codes that use MMT_SEC_PLUGINS_REPOSITORY_OPT to update the new directory.
# The following target will remove the object files of the codes, thus it will trigger to recompile them.
# So, in the example above, the MMT_SEC_PLUGINS_REPOSITORY_OPT will be update to /tmp/mmt/security/rules.
	
--refresh-plugin-engine:
	$(QUIET) echo [RE-COMPILE] plugins_engine.o
	$(QUIET) $(CC) $(CFLAGS) $(CLDFLAGS) $(CFLAG-PLUGINS-ENGINE) -c -o $(SRCDIR)/lib/plugins_engine.o $(SRCDIR)/lib/plugins_engine.c


# RULE_OBJS is a list of .o files of rules
#   This list is empty if we compile without STATIC_LINK option
# The object lists must be prerequisites, otherwise -j may archive or link
# the library before every object exists (missing-file error from ar/ld).
$(LIB_NAME).a: $(LIB_OBJS) $(RULE_OBJS)
	$(QUIET) echo "[ARCHIVE] $(notdir $@)"
	$(QUIET) $(AR) $(LIB_NAME).a  $(LIB_OBJS) $(RULE_OBJS)

	@#$(QUIET) $(RM) $(RULE_OBJS) #we do not need rules/*.o anymore

$(LIB_NAME).so: $(LIB_OBJS) $(RULE_OBJS)
	@echo "[LIBRARY] $(notdir $@)"
	$(QUIET) $(CC)  -fPIC -shared -O3 -o $(LIB_NAME).so $(CLDFLAGS) $(LIB_OBJS)  $(RULE_OBJS)
	
lib:  $(LIB_OBJS)  $(RULE_OBJS) --refresh-plugin-engine $(LIB_NAME).a $(LIB_NAME).so
	
uninstall:
	$(QUIET) $(RM) $(INSTALL_DIR)
	
ifdef NEED_ROOT_PERMISSION
	$(QUIET) $(RM) /etc/ld.so.conf.d/mmt-security.conf
endif


# RULE_GCC_ARGS is one option string that compile_rule appends verbatim to
# the gcc command line; it takes a single optional argument (argc <= 4).
# It is quoted so several flags - an ASAN+UBSAN build passes
# '-fsanitize=address -fsanitize=undefined' - still reach it as one shell
# word, and left absent entirely when empty (an "" would add a stray
# argument and a trailing space in the recorded cflags).
# The .xml is a normal prerequisite: without it a `make` after a rule
# edit kept the stale .so and `make check` tested the old rule (fork #70).
# compile_rule is the generator input; a rebuilt one regenerates every rule.
rules/%.so: rules/%.xml compile_rule $(FLAVOR_DEP)
	$(QUIET) ./$(MAIN_GEN_PLUGIN) rules/$*.so rules/$*.xml $(if $(RULE_GCC_ARGS),"$(RULE_GCC_ARGS)")
	
sample_rules: $(SAMPLE_RULES)


# create a temporal folder
TMP_DIR := build_mmt_security

# copy_files stages the built rules, binaries and libs: as a sibling
# prerequisite of install/deb/rpm a parallel make could run it before
# sample_rules finished and `cp rules/*.so` would fail (fork #70)
copy_files: all sample_rules
	$(QUIET) $(RM)    $(TMP_DIR) 2> /dev/null
	$(QUIET) $(MKDIR) $(TMP_DIR)/rules
	
ifndef STATIC_LINK
	$(QUIET) $(CP)    rules/*.so $(TMP_DIR)/rules/
endif

	$(QUIET) $(CP)    mmt-security.conf  $(TMP_DIR)/
	
	$(QUIET) $(MKDIR) $(TMP_DIR)/include
	$(QUIET) $(CP)    $(SRCDIR)/dpi/* $(filter-out $(SRCDIR)/lib/rule_verif_engine_internal.h,$(wildcard $(SRCDIR)/lib/*.h)) $(TMP_DIR)/include/
	
	$(QUIET) $(MKDIR) $(TMP_DIR)/bin
	$(QUIET) $(CP)    $(MAIN_GEN_PLUGIN)  $(MAIN_PLUGIN_INFO)  $(TMP_DIR)/bin
	$(QUIET) $(CP)    $(MAIN_STAND_ALONE) $(TMP_DIR)/bin/mmt_security
	$(QUIET) $(CP)    $(MAIN_SEC_SERVER)  $(TMP_DIR)/bin/
	
	$(QUIET) $(MKDIR) $(TMP_DIR)/lib
	$(QUIET) $(MV)    $(LIB_NAME).so      $(TMP_DIR)/lib/$(LIB_NAME).so.$(VERSION)
	$(QUIET) $(MV)    $(LIB_NAME).a       $(TMP_DIR)/lib/$(LIB_NAME).a.$(VERSION)
	
	$(QUIET) $(RM)  $(TMP_DIR)/lib/$(LIB_NAME).so $(TMP_DIR)/lib/$(LIB_NAME).a
	
ifdef REDIS
	$(QUIET) $(CP) /usr/local/lib/libhiredis.so.0.13 $(TMP_DIR)/lib/
endif

#create symbolic links	
	$(QUIET) cd $(TMP_DIR)/lib/ && $(LN)  $(LIB_NAME).so.$(VERSION) $(LIB_NAME).so
	$(QUIET) cd $(TMP_DIR)/lib/ && $(LN)  $(LIB_NAME).a.$(VERSION)  $(LIB_NAME).a
	
	
install: all sample_rules uninstall copy_files
	$(QUIET) $(MKDIR) $(INSTALL_DIR)
	$(QUIET) $(MV)    $(TMP_DIR)/* $(INSTALL_DIR)
	$(QUIET) $(RM)    $(TMP_DIR)
	
ifdef NEED_ROOT_PERMISSION
	@echo "$(INSTALL_DIR)/lib" >> /etc/ld.so.conf.d/mmt-security.conf
	@ldconfig
endif

	@echo ""
	@echo "INFO: Installed successfully MMT-Security in $(INSTALL_DIR)"
	
	
DEB_NAME = mmt-security_$(VERSION)_$(GIT_VERSION)_$(shell uname -s)_$(shell uname -m)

#Depends: the packages of the shared libraries the packaged binaries are
# linked to (the libxml2 soname differs by release), resolved by
# dpkg-shlibdeps (dpkg-dev); its mmt-dpi entry is replaced by the
# MIN_DPI_VERSION bound, which also covers an mmt-dpi installed without
# a package (--ignore-missing-info). dpkg-shlibdeps wants a
# debian/control in the current directory; a minimal one is lent to it
# inside the package tree and removed before dpkg-deb runs.
#The whole recipe is one shell: the trap removes the staging dir and the
# .shlibs-deps file on any failing step, so a failed run leaves nothing
# behind — and a stale staging dir from a previous (killed or failed) run
# is removed first, which a non-empty dir would otherwise break mv on
# (fork #47)
deb: all lib sample_rules copy_files
	$(QUIET) set -e; \
	trap 's=$$?; if [ $$s -ne 0 ]; then $(RM) $(DEB_NAME) $(DEB_NAME).shlibs-deps; fi; exit $$s' EXIT; \
	$(RM) $(DEB_NAME); \
	$(MKDIR) $(DEB_NAME)/DEBIAN $(DEB_NAME)/$(INSTALL_DIR); \
	$(MV) $(TMP_DIR)/* $(DEB_NAME)/$(INSTALL_DIR); \
	$(RM) $(TMP_DIR); \
	\
	( cd $(DEB_NAME) \
		&& $(MKDIR) debian \
		&& printf 'Source: mmt-security\nPackage: mmt-security\n' > debian/control \
		&& dpkg-shlibdeps --ignore-missing-info -l$(MMT_DPI_DIR)/lib -O \
			.$(INSTALL_DIR)/bin/* .$(INSTALL_DIR)/lib/$(LIB_NAME).so.$(VERSION); \
		s=$$?; $(RM) debian; exit $$s ) > $(DEB_NAME).shlibs-deps; \
	shlibs=`sed -n 's/^shlibs:Depends=//p' $(DEB_NAME).shlibs-deps \
		| sed 's/mmt-dpi ([^,]*)//g; s/, ,/,/g; s/^, //; s/, $$//'`; \
	$(RM) $(DEB_NAME).shlibs-deps; \
	printf '%s\n' \
		'Package: mmt-security' \
		'Version: $(VERSION)' \
		'Section: base' \
		'Priority: standard' \
		'Architecture: $(shell dpkg --print-architecture)' \
		'Maintainer: Montimage <contact@montimage.com>' \
		"Depends: mmt-dpi (>= $(MIN_DPI_VERSION))$${shlibs:+, $$shlibs}" \
		'Description: MMT-Security: An intrusion detection system' \
		"  Version id: $(GIT_VERSION). Build time: `date +'%Y-%m-%d %H:%M:%S'`" \
		'Homepage: http://www.montimage.com' \
		> $(DEB_NAME)/DEBIAN/control; \
	\
	$(MKDIR) $(DEB_NAME)/etc/ld.so.conf.d/; \
	echo "$(INSTALL_DIR)/lib" > $(DEB_NAME)/etc/ld.so.conf.d/mmt-security.conf; \
	\
	dpkg-deb --root-owner-group -b $(DEB_NAME); \
	$(RM) $(DEB_NAME)
	
	
#create rpm file for RHEL
rpm: all lib sample_rules copy_files
	
#create rpm structure (no brace expansion: /bin/sh may be dash)
	$(QUIET) $(MKDIR) ./rpmbuild/RPMS ./rpmbuild/BUILD

	@#the spec is written with printf: echo -e is a bashism, dash does not
	@# know it and would print "-e" as the spec's first line
	$(QUIET) printf '%s\n' \
		"Summary:  MMT-Security:  An intrusion detection system" \
		"Name: mmt-security" \
		"Version: $(VERSION)" \
		"Release: $(GIT_VERSION)" \
		"License: proprietary" \
		"Group: Development/Libraries" \
		"URL: http://montimage.com/" \
		"" \
		"Requires:  mmt-dpi >= $(MIN_DPI_VERSION)" \
		"BuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}" \
		"" \
		"%description" \
		"MMT-Security is a library using MMT-DPI to detect abnormalities in network." \
		"Build date: `date +'%Y-%m-%d %H:%M:%S'`" \
		"" \
		"%prep" \
		"rm -rf %{buildroot}" \
		"mkdir -p %{buildroot}/$(INSTALL_DIR)" \
		"cp -rL \"$(abspath $(TMP_DIR))\"/* %{buildroot}/$(INSTALL_DIR)" \
		"mkdir -p %{buildroot}/etc/ld.so.conf.d/" \
		"echo \"$(INSTALL_DIR)/lib\" >> %{buildroot}/etc/ld.so.conf.d/mmt-security.conf" \
		"" \
		"%clean" \
		"rm -rf %{buildroot}" \
		"" \
		"%files" \
		"%defattr(-,root,root,-)" \
		"$(INSTALL_DIR)/*" \
		"/etc/ld.so.conf.d/mmt-security.conf" \
		"%post" \
		"ldconfig" \
		> ./mmt-security.spec
	
	$(QUIET) rpmbuild --quiet --rmspec --define "_topdir $(shell pwd)/rpmbuild" --define "_rpmfilename ../../$(DEB_NAME).rpm" -bb ./mmt-security.spec
	$(QUIET) $(RM) $(TMP_DIR) rpmbuild
	@echo "[PACKAGE] $(DEB_NAME).rpm"
		
dist-clean: uninstall
	@echo "INFO: Removed successfully MMT-Security from $(INSTALL_DIR)"

clean-rules:
	$(QUIET) $(RM) rules/*.so rules/*.o rules/*.c
clean: clean-rules
	$(QUIET) $(RM) $(LIB_NAME).* $(MAIN_OBJS) $(LIB_OBJS) $(OUTPUT) test.* \
			$(SRCDIR)/lib/*.gen.o $(SRCDIR)/*.gen.o \
			$(MAIN_DPI) $(MAIN_GEN_PLUGIN) $(MAIN_PLUGIN_INFO) $(MAIN_STAND_ALONE) $(MAIN_SEC_SERVER)\
			$(RULE_OBJS) $(TMP_DIR) $(FLAVOR_STAMP)

clean-all: clean
	$(QUIET) $(RM) $(MMT_DPI_HEADER) $(MMT_DPI_HEADER).new*
	
################################################################################
# Auto test 
################################################################################
NAMES := $(sort $(patsubst check/pcap/%.pcap,%, $(wildcard check/pcap/*.pcap)))

ifdef VAL
  VALGRIND = valgrind --leak-check=yes
else
  VALGRIND =
endif

TEST_INDEX=1
# options of mmt_sec_standalone for check/pcap/X.pcap, read from check/pcap/X.opt if it exists (e.g. -R)
CHECK_OPT = $(shell cat check/pcap/$*.opt 2>/dev/null)
# environment variables for check/pcap/X.pcap, read from check/pcap/X.env if it exists (e.g. MMT_SEC_HTTP2_SEED=1):
# NAME=value pairs, separated by spaces or lines, with no '#' comment and no double quote
# (the file is expanded inside the bash -c "..." of _check.% and _csv.%)
CHECK_ENV = $(shell cat check/pcap/$*.env 2>/dev/null)
_prepare: compile_rule standalone sample_rules
	@echo "==============================="
check/expect/%.csv :
	@echo "  => not found expected result: $@"
	@exit 1
check/pcap/%.pcap :
	@echo "  => not found sample pcap file: $@"
	@exit 1
_print.%:
	@echo
	@echo "$(TEST_INDEX). Testing $*"
	$(eval TEST_INDEX=$(shell echo $$(($(TEST_INDEX)+1))))
#one test
_check.%: _print.% check/expect/%.csv check/pcap/%.pcap
	$(QUIET) $(RM) /tmp/mmt-security*.csv
	$(QUIET) bash -c "$(CHECK_ENV) $(VALGRIND) ./$(MAIN_STAND_ALONE) $(CHECK_OPT) -t check/pcap/$*.pcap -f /tmp/"
#starting by rule id (rm timestamp, filename, probe-id)
	$(QUIET) bash -c "cut -d, -f5- /tmp/mmt-security*.csv  > /tmp/mmt-security-res.csv"
	$(QUIET) bash -c "cut -d, -f5- check/expect/$*.csv     > /tmp/mmt-security-expect.csv"
#get set of rules
	$(QUIET) bash -c "cut -d, -f1 /tmp/mmt-security-expect.csv | sort | uniq > /tmp/mmt-security-expect-rule-id.csv"
	$(QUIET) cat /tmp/mmt-security-expect-rule-id.csv
#get only verdicts of the rules listed in the expected file (exact rule-id match, e.g. ^(4|5|56),)
# an empty expected file keeps every alert, i.e. the test expects no alert at all
# grep exits 1 when nothing matches (no alert of these rules): not an error
	$(QUIET) bash -c 'ids=$$(grep -v "^$$" /tmp/mmt-security-expect-rule-id.csv | paste -sd "|"); \
		if [ -z "$$ids" ]; then cp /tmp/mmt-security-res.csv /tmp/mmt-security-result.csv; \
		else grep -E "^($$ids)," /tmp/mmt-security-res.csv > /tmp/mmt-security-result.csv; [ $$? -le 1 ]; fi'
	$(QUIET) wc -l /tmp/mmt-security-expect.csv
	$(QUIET) wc -l /tmp/mmt-security-result.csv
	$(QUIET) bash -c 'diff --ignore-all-space /tmp/mmt-security-expect.csv /tmp/mmt-security-result.csv || { echo "  => FAILED: alerts of check/pcap/$*.pcap differ from check/expect/$*.csv (diff above)"; exit 1; }'
	@echo '  => OK'
	
#negative tests of compile_rule: malformed rules must give an error, not a crash
_check_compile_rule: compile_rule
	@echo
	@echo "Testing compile_rule on malformed rules"
	$(QUIET) bash check/rules_compile.sh ./$(MAIN_GEN_PLUGIN)

check: check-properties-all check-rule-hooks _prepare _check_compile_rule $(patsubst %,_check.%,$(NAMES)) check-build-info
	@echo "All test passed!"

# rules 97 and 98 free the state of every verification thread (needs valgrind)
check-valgrind: standalone sample_rules
	@echo
	@echo "Testing the per-thread state of rules 97 and 98 under valgrind"
	$(QUIET) bash check/h2_thread_leak.sh

# make _csv.X uses check/pcap/X.env, as make _check.X does
check: check-csv-env
check-csv-env:
	@./check/check-csv-env.sh

# build info embedded in every rule .so (doc/rule.md)
check-build-info: compile_rule rule_info standalone sample_rules
	@echo
	@echo "Testing the build info of rule .so files"
	$(QUIET) test/build_info/check.sh $(VERSION) $(GIT_VERSION)

# every rules/*.xml must have a copy in rules/properties_all/ (see readme.md)
check-properties-all:
	@missing=0; \
	for f in rules/*.xml; do \
		[ -f "rules/properties_all/$$(basename $$f)" ] || { echo "  => missing copy: rules/properties_all/$$(basename $$f)"; missing=1; }; \
	done; \
	[ $$missing -eq 0 ] || exit 1
	@echo "All rules/*.xml have a copy in rules/properties_all/"

# the DICOM rules' shared C blocks match check/gen/dicom/blocks/ and compile on their own
check: check-dicom-blocks
check-dicom-blocks:
	@./check/dicom-blocks.sh -I $(MMT_DPI_DIR)/include

# no rule may define on_load/on_unload as static: dlsym() would not find them
check-rule-hooks:
	@./check/check-rule-hooks.sh

# the comparisons that compile_rule generates: numeric operations, strings (fork #31)
check: check-expressions
check-expressions: _prepare
	@./check/check-expressions.sh ./$(MAIN_GEN_PLUGIN) ./$(MAIN_STAND_ALONE)

# rules 56 and 57: environment variables, cost of a fast flood, threads
check: check-syn-flood-rules
check-syn-flood-rules: _prepare
	@./check/check-syn-flood-rules.sh ./$(MAIN_STAND_ALONE)

# NOT/THEN timeout verdict path of the rule verification engine (fork #31)
check: check-timeout
check-timeout: _prepare
	@./check/check-timeout.sh ./$(MAIN_GEN_PLUGIN) ./$(MAIN_STAND_ALONE)

# SMP mode of mmt_sec_standalone: bounded -c runs, SIGTERM stops a run (fork #31)
check: check-smp
check-smp: _prepare
	@./check/check-smp.sh ./$(MAIN_STAND_ALONE)

# SMP workers of mmt_sec_server: SIGTERM must stop the parent and a forked
# child mid-stream, not deadlock in the signal handler (fork #31)
check: check-smp-server
check-smp-server: _prepare sec_server rule_info
	@./check/check-smp-server.sh ./$(MAIN_SEC_SERVER)

# bounds checks of mmt_fsm.c: a crafted fsm must be rejected AND log an
# mmt_error - a silent return would hide a corruption precursor (fork #45)
check: check-fsm-bounds
check-fsm-bounds: _prepare
	@./check/check-fsm-bounds.sh

# unload then load of rule plugins: vacated plugin slots, counts and ids,
# and an alert run on the reloaded rules (issue #58)
check: check-unload-rules
check-unload-rules: _prepare
	@./check/check-unload-rules.sh

# -h/--help exits 0 and a bad option exits 1 for every tool (fork #47)
check: check-help
check-help: _prepare sec_server rule_info
	@./check/check-help.sh ./$(MAIN_STAND_ALONE) ./$(MAIN_SEC_SERVER) ./$(MAIN_PLUGIN_INFO) ./$(MAIN_GEN_PLUGIN)

# compile_rule keys no event whose expression calls an embedded function
# before an equality of the key (fork #51, PR #55)
check: check-instance-keys
check-instance-keys: compile_rule
	@./check/check-instance-keys.sh ./$(MAIN_GEN_PLUGIN)

# the loader refuses rule .so files of another plugin ABI, older or newer,
# with a warning instead of loading them (fork #51, PR #55)
check: check-plugin-abi
check-plugin-abi: _prepare rule_info
	@./check/check-plugin-abi.sh ./$(MAIN_GEN_PLUGIN) ./$(MAIN_STAND_ALONE) ./$(MAIN_PLUGIN_INFO)

# message_t alignment (issue #64): check/message_align.c run under
# ASan+UBSan asserts every message_t block is _Alignof(message_t)-aligned
check: check-message-align
check-message-align: _prepare
	@./check/check-message-align.sh

# UBSan on the embedded element headers of message_t (fork #66): a UBSan
# build of the library and the rules in a scratch copy (the normal build is
# untouched), then every check/pcap single-threaded and `-c 1-8`; no
# misaligned-access report may remain
check: check-ubsan-align
check-ubsan-align:
	@./check/check-ubsan-align.sh

# ThreadSanitizer on the SMP message hand-off (fork #45): a TSan build in a
# scratch copy (the normal build is untouched), then `-c 1-8` on every
# check/pcap, all rules and rule 54 alone; no report may remain unexplained
# (check/tsan_suppressions.txt holds the explained false positives)
check: check-tsan
check-tsan:
	@./check/check-tsan.sh

# build-flavor stamp (fork #54): plain, then TSAN=1, then ASAN=1 in a scratch
# copy, and nm asserts every object linked into mmt_sec_standalone,
# libmmt_security2 and the rules/*.so carries the flavor's marker - except
# the uninstrumented compile_rule objects. Fails when a flavor switch links
# objects of another flavor.
check: check-flavor
check-flavor:
	@./check/check-flavor.sh

# a touched rules/%.xml must rebuild its rules/%.so (and only it), a second
# make must be a no-op, and a newer compile_rule rebuilds every rule; the
# STATIC_LINK rules/%.c tracks its .xml the same way (fork #70)
check: check-rule-deps
check-rule-deps: _prepare
	@CC='$(CC)' ./check/check-rule-deps.sh

_csv.%: _prepare
	$(QUIET) $(RM) /tmp/mmt-security*.csv
	$(QUIET) bash -c "$(CHECK_ENV) ./$(MAIN_STAND_ALONE) -v $(CHECK_OPT) -t check/pcap/$*.pcap -f /tmp/" || exit 1
	$(QUIET) find /tmp/mmt-security*.csv -exec mv {} check/expect/$*.csv \;
	
csv: $(patsubst %,_csv.%,$(NAMES))
################################################################################
