# 1. Sample rules

There are sample rules in [../rules/](../rules/)

## 1.1 Delay and counter values

The attributes `delay_min`, `delay_max`, `counter_min` and `counter_max` of a `<property>` or an `<operator>` take a non-negative integer, optionally followed by one sign:

- `N`: the bound is inclusive, e.g., `delay_max="10"`;
- `N+`: the bound is strict from below, e.g., `delay_min="0+"` means strictly after the first event;
- `N-`: the bound is strict from above, e.g., `delay_max="10-"` means strictly less than 10 units.

`delay_units` gives the unit of `delay_min` and `delay_max`: `Y`, `M`, `D`, `h`, `m`, `s` (default), `ms` or `mms` (microseconds).

`compile_rule` rejects any other value, e.g., `"0++"`, `"1s"`, `"0.5"` or a negative number, with an error that names the attribute, and exits with a non-zero code.


# 2. Embedded functions

Embedded functions are functions that allow implementing calculations 
that are too complicated to define using only classical operators on fields in the Boolean expressions of security rules. 
One can either use existing embedded functions or implement a new function. 
In both cases, they can be used in the Boolean expressions by using the syntax:

  `#<name_of_function>(<list of parameters>)`

For example:

  `(#em_is_search_engine( http.user_agent ) == true)`
   
where `http` is the protocol name and `user_agent` is the attribute name (i.e., packet meta-data).

**To avoid any confusion**, a new embedded function name should start by a prefix `em_`.

## 2.1. Special terms

1. `true` will be replaced by the number 1. For example 

  `#em_check( tcp.src_port ) == true`

2. `false` will be replaced by the number 0. For example 

  `#em_check( tcp.src_port ) == false`


## 2.2 Implement a new embedded function
In each rule file, there exists a section allowing user to add an embedded function.

```xml
<embedded_functions><![CDATA[
//code C
static inline bool em_check( double port ){
   if( port == 80 || port == 8080 )
      return true;
   return false;
}
]]></embedded_functions>
```

In side this tag, one can also implement 2 other functions as the followings:

1. `void on_load(){ ... }` being called when the rules inside the xml file being loaded into MMT-Security

2. `void on_unload(){ ... }` being called when exiting MMT-Security


## 2.3 Pre-installed embedded functions

In boolean expressions of rules, one can use one or many embedded functions

1. `is_exist( proto.att )`  checks whether an event has an attribute of a protocol, e.g., `is_exist( http.method )` will return `true` if the current event contains protocol `HTTP` and attribute method has a non-null value, otherwise it will return `false`.

	Normally MMT has a filter that allow an event in a rule to be verified only if any proto.att used in its boolean expression contains value. If one of them has not, the rule will not be verified. This allows to reduce number of verification of boolean expression, thus increases the performance.
	
	For example, given an event having the following boolean expression:
	
	`((ip.src != ip.dst) && (#em_check_URI(http.uri) == 1))`
	
	This event is verified only if `ip.src` and `ip.dst` and `http.uri` are not null, hence only HTTP packets are verified (it does not verify every IP packets).
	
	However, if one use the following expression, that is totally having the same meaning with the previous one:
	
	`((ip.src != ip.dst) && ((#is_exist(http.uri) == true ) && (#em_check_URI(http.uri) == 1)))`
	
	MMT need to verify the expression against any IP packet as `is_exist` tell MMT to exclude `http.uri` from its filter.
	

2. `is_empty( proto.att )`, e.g., `is_empty(http.uri)` checks whether the string value is empty, i.e., its length is zero.

3. User can use any standard C functions as embedded function, e.g., `(#strstr( http.user_agent, 'robot') != 0)` to check if `http.user_agent` contains a sub-string `"robot"`.

   Please note that, before using a C function the library containing that embedded functions need to be included.
   The following libraries have been pre-included:
   
```C
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "mmt_lib.h"
#include "pre_embedded_functions.h"
```

   Thus when using a function that does not defined inside these libraries, one need to include its library. For example:
   
```xml
<embedded_functions><![CDATA[
#include <math.h>

static inline bool function em_check( double port ){
    double x = sqrt( port );
    ...
}
]]></embedded_functions>
```
   
# 3. Reactive functions
   
Reactive functions allow user perform some action when a rule is satisfied.
The functions will be called each time their rules are satisfied. 
When a security and attack rules are satisfied, they will give `not_respected` and `detected` verdicts respectively.

To implement and use a reactive function, one need:

- implement a C function inside `embedded_functions` tag. The function name should be prefixed by `em_` to avoid any confusion with the ones existing in MMT.

  The function has the following format:

```C
typedef void (*mmt_rule_satisfied_callback)(
		const rule_t *rule,		          //rule being validated
		int verdict,                     //DETECTED, NOT_RESPECTED
		uint64_t timestamp,              //moment (by time) the rule is validated
		uint64_t counter,                //moment (by order of message) the rule is validated
		const mmt_array_t * const trace  //historic of messages that validates the rule
);
```
   
- put the function name in attribute `if_satisfied` of the rule you want to react. For example: `if_satisfied="em_print_out"`


```xml
<beginning>
<embedded_functions><![CDATA[
static void em_print_out(
      const rule_info_t *rule, int verdict, uint64_t timestamp, 
      uint64_t counter, const mmt_array_t * const trace ){
   const char* trace_str = mmt_convert_execution_trace_to_json_string( trace, rule );
   printf( "detect rule %d\n%s\n", rule->id, trace_str );
   //you can call a system command, for example:
   //char command[1001];
   //snprintf( command, 1000, "echo rule %d is validated by %s", rule->id, trace_str );
   //system( command );
}
]]></embedded_functions>

<!-- Property 10: HTTP using a port different from 80 and 8080.-->
<property value="THEN" delay_units="s" delay_min="0" delay_max="0" property_id="10" type_property="EVASION" 
    description="HTTP using a port different from 80 and 8080." if_satisfied="em_print_out">
    <event value="COMPUTE" event_id="1" 
        description="HTTP packet using a port different from 80 and 8080"
           boolean_expression="((http.method != '')&amp;&amp;((tcp.dest_port != 80)&amp;&amp;(tcp.dest_port != 8080)))"/>
    <event value="COMPUTE" event_id="2" 
           description="HTTP packet"
           boolean_expression="(ip.src != ip.dst)"/>
</property>
</beginning>
```

# 4. Compile rules

MMT-Security rules are specified in plain text following a XML format.
These rules need to be encoded in a suitable format, that is a dynamic C library, before being able to use by MMT-Security.

The compiled rules must put in either `./rules` or `/opt/mmt/security/rules`.
The former has higher priority and only one of them will be taken into account by MMT-Security.
Specifically, if MMT-Security found `./rules` folder in the current folder executing, it will use the rules inside this folder and
it does not take into account the rules in `/opt/mmt/security/rules`.

## 4.1 Compile rules
MMT-Security provides a compiler to do the such of task. Its source code is in [`src/main_gen_plugin.c`](../src/main_gen_plugin.c) file.

- use `make compile_rule` to compile this program to get an executable program `compile_rule`

- use `compile_rule` to compile rules in a XML file. For example:

   `./compile_rule rules/1.so rules/1.ssh.xml`
   
   The program uses 3 parameters in form: `./compile_rule output_file property_file "[gcc parameters]"`

   where:

   - `output_file`: is the path of file containing the result that can be either a .c file or .so file.
   - `property_file`: is the path where the property file can be found.
   - `options`: 
      
      - `-c`: will generate only the C code. This option allows manually modifying the generated code before compiling it. 
       After generating the C code, the tool prints out the command that needs to be executed for compiling it.
       
       - gcc parameters: used to generate the C code, and compile it to obtain the .so file.
                      These parameters will be directly transmitted to the gcc compiler, for example, `"-I /tmp -lmath"`
       
Please note that, the compiled rules must be put in the directory `./rules` or `/opt/mmt/security/rules/`

## 4.2 Obtain information inside compiled rules 

To get some basic information about a compiled rule (such as, ID, description) MMT provides a tool:
[`src/main_plugin_info.c`](../src/main_plugin_info.c)

- use `make rule_info` to obtain its executable program
- use `./rule_info` to print information of all compiled rules in `./rules` or `/opt/mmt/security/rules/`

   By default, the tool will print out the information on all rules, for example:
   
```
./rule_info 
Found 37 rules.
1 - Rule id: 1
	- type            : attack
	- events_count    : 4
	- variables_count : 5
	- variables       : ip.dst (178.13), ip.src (178.12), tcp.dest_port (354.2), tcp.flags (354.6), tcp.src_port (354.1)
	- description     : Several attempts to connect via ssh (brute force attack). Source address is either infected machine or attacker (no spoofing is possible).
	- if_satisfied    : (nil)
	- version         : 1.1.5 (70a367f - 2017-6-8 12:42:25), dpi version 1.6.8.0 (b3e727b)
2 - Rule id: 10
	- type            : evasion
	- events_count    : 2
   ...
...
```

- The tool can also be used to inspect a specific compiled rule by giving the rule path as parameter, for example:

```
./rule_info /opt/mmt/security/rules/4.arp.so 
Found 1 rule.
1 - Rule id: 4
	- type            : attack
	- events_count    : 3
	- variables_count : 7
	- variables       : arp.ar_op (30.5), arp.ar_sha (30.6), arp.ar_sip (30.7), arp.ar_tip (30.9), ethernet.dst (99.2), ethernet.packet_count (99.4099), ethernet.src (99.3)
	- description     : IPv4 address conflict detection (RFC5227). Possible arp poisoning.
	- if_satisfied    : (nil)
	- version         : 1.1.5 (70a367f - 2017-6-8 12:42:28), dpi version 1.6.8.0 (b3e727b)
```
 
## 4.3 Build information of a compiled rule

Every `.so` built by `compile_rule` records the environment it was built in. A
deployment can therefore check that it fits the target system: the same rule
ABI, the same mmt-dpi ids, the plugins it needs, the glibc it needs. The
information is one JSON document, stored twice:

- returned by the exported function `const char *mmt_sec_get_rule_build_info(void)`.
  With `STATIC_LINK`, the name gets the rule's `RULE_SUFFIX`, like
  `mmt_sec_get_plugin_info`;
- in the ELF note section `.note.mmt.build` (owner `MMT`, type `0x4d4d5401`),
  readable without loading the `.so`.

```bash
./rule_info --build-info rules/13.datainSYN.so          # indented
./rule_info --build-info --json rules/13.datainSYN.so   # one line, for scripts
readelf -n rules/13.datainSYN.so                         # the note (hex dump)
readelf -p .note.mmt.build rules/13.datainSYN.so         # the note as text
./rule_info --abi                                        # the rule ABI of this mmt-security
```

`rule_info --build-info` reads the note, without loading the `.so`; it calls
the function only when the file has no note. A `.so` built before the build
info existed has neither: it still loads and runs as before. `rule_info
--build-info` then says so, and `--json` prints `null`. A file that is not an
ELF shared object of this architecture, or whose section table or notes are
malformed, is an error (exit code 1): the reader checks every offset and size,
since it is meant for `.so` files that are not trusted yet. The existing `rule_version_info_t`
(`mmt_sec_get_rule_version_info`, `version` in `rule_info_t`) is unchanged.

Example (rule 13, built in ubuntu:24.04 with mmt-dpi 1.10.3 installed):

```json
{
  "schema": 1,
  "rule_ids": [13],
  "xml": {"file": "13.datainSYN.xml", "sha256": "ee66f765...2225"},
  "rule_abi": {"hash": "sha256:cdf30484...146a", "plugin_version": "1.2.7"},
  "mmt_security": {"version": "1.2.20", "git": "0e2f9cb", "index": 1022000},
  "dpi": {
    "ids_from": "1.7.10 (fd93012d)", "ids_from_commit": "fd93012d",
    "installed": "1.10.3 (6a0afb46)", "installed_commit": "6a0afb46",
    "ids_match_installed": true,
    "ids_hash": "sha256:1f88c382...1979",
    "ids": [["ip", 178, "dst", 14, 8], ["ip", 178, "src", 13, 8],
            ["tcp", 354, "flags", 6, 1], ["tcp", 354, "payload_len", 27, 3]],
    "plugins": ["libmmt_tcpip.so"]
  },
  "build": {
    "compiler": "gcc 13.3.0", "target": "aarch64-linux-gnu",
    "cflags": "-O3 -fPIC -shared {source} -o {output} -I ./src/lib -I ./src/dpi -I/opt/mmt/security/include -I/opt/mmt/dpi/include",
    "glibc_min": "GLIBC_2.17", "os": "Ubuntu 24.04.5 LTS",
    "builder": null, "date": "2026-11-20T13:39:08Z"
  }
}
```

| field | meaning |
|---|---|
| `schema` | version of this layout (1). It is bumped when a field changes meaning. |
| `rule_ids` | ids of the rules in the `.so` |
| `xml.file`, `xml.sha256` | name of the rule XML, and the SHA-256 of its bytes |
| `rule_abi.hash` | `sha256:` of the layout (`sizeof`/`offsetof`) of the structures a rule shares with the engine: `rule_info_t`, `proto_attribute_t`, `rule_version_info_t`, `message_t`, `message_element_t`, `mmt_array_t`, plus `REQUIRE_PLUGIN`. `rule_info --abi` prints the engine's layout and hash. |
| `rule_abi.plugin_version` | `REQUIRE_PLUGIN`: the oldest rule version this mmt-security loads |
| `mmt_security.version`, `.git`, `.index` | the mmt-security that compiled the rule (same as `rule_version_info_t`) |
| `dpi.ids_from`, `.ids_from_commit` | the label (`mmt_version()`) of the DPI header compiled into `compile_rule`, and its commit. `compile_rule` takes the ids from that header's table, compiled in with it, not from the installed mmt-dpi. It is neither the `src/dpi/mmt_dpi.h` on disk nor the installed mmt-dpi: `make` can regenerate that file without rebuilding `compile_rule`, and the label can be wrong about the table (the committed header says `fd93012d` and holds 6b1c9f53's table). See [rule-abi-stability.md](rule-abi-stability.md#how-the-ids-get-into-a-rule-so). The ids themselves are `dpi.ids`. |
| `dpi.installed`, `.installed_commit` | a separate fact: `mmt_version()` of the `libmmt_core` that `compile_rule` found with `dlopen` where it ran (`compile_rule` does not link it), or `null` if none was found. The ids do not come from it. |
| `dpi.ids_match_installed` | `true` when every pair below resolves to the same ids and type in that installed `libmmt_core`, `false` when one differs, `null` if unknown |
| `dpi.ids` | every `[proto, proto_id, att, att_id, dpi_type]` the rules use, as baked into the `.so`, sorted by proto then att |
| `dpi.ids_hash` | `sha256:` of one line `proto,proto_id,att,att_id,dpi_type\n` per entry of `dpi.ids`, in that order (byte-wise sort on proto, then att) |
| `dpi.plugins` | the plugin files of the installed mmt-dpi that register the protocols the rules use (found by `dladdr` on the protocol name each plugin gives mmt-dpi) or extract their attributes (`dladdr` on each attribute's extraction function), sorted. A `.so` needs them loaded by the engine's mmt-dpi. `libmmt_core` is not a plugin and is not listed, nor are its own protocols (`meta`, `unknown`), so a rule that uses only those has `[]`. `null` if no mmt-dpi was found. |
| `build.compiler` | compiler of the `.so`, from its predefined macros (`gcc __VERSION__` or `clang __clang_version__`) |
| `build.target` | target of that compiler, from its predefined macros (`__x86_64__`, `__aarch64__`, `__linux__`, `__GLIBC__`...), named as `gcc -dumpmachine` names it, e.g. `x86_64-linux-gnu`. With `-m32` it is `i686-linux-gnu`. A vendor part `gcc -dumpmachine` may add is not in the macros and not recorded (Red Hat's `aarch64-redhat-linux` gives `aarch64-linux-gnu`). |
| `build.cflags` | the arguments `compile_rule` passed to `/usr/bin/gcc`, in their order, with the C file written `{source}` and the `.so` written `{output}`. The extra option of `compile_rule` comes last, after the source, so its `-l` libraries are linked. `null` with `-c`, where the C is compiled elsewhere. |
| `build.glibc_min` | highest `GLIBC_x.y` symbol version the `.so` needs. `compile_rule` links twice to measure it. `null` with `-c`. |
| `build.os` | `PRETTY_NAME` of `/etc/os-release` |
| `build.builder` | `$MMT_SEC_BUILDER`, or `null` when it is not set. The host name is not recorded, since the `.so` may be distributed. CI sets it to the URL of the run. |
| `build.date` | UTC build time, or `$SOURCE_DATE_EPOCH` when set; `null` when that time has no date (`gmtime_r` fails) or `$SOURCE_DATE_EPOCH` is not a number |

Every string is UTF-8: a byte that is not valid UTF-8 (e.g., in a Latin-1 file
name) becomes U+FFFD. `compile_rule` rejects an extra gcc option longer than
about 9,900 bytes with an error, instead of truncating it.

`MMT_SEC_BUILD_INFO_NO_DPI=1` makes `compile_rule` skip looking for an
installed mmt-dpi (`dpi.installed`, `ids_match_installed` and `plugins` are then
`null`).

## 4.4 Comparisons in a boolean expression

A comparison (`==`, `!=`, `<`, `<=`, `>`, `>=`) compares two numbers or two
strings:

- two numbers compare as numbers, including arithmetic, e.g.,
  `(udp.dest_port - udp.src_port) < (udp.len - 8)`;
- two strings: when every operand is a string attribute, e.g.,
  `http.method < http.user_agent`, the order is the one of `mmt_mem_cmp` —
  **the data size first, then `memcmp`** — so `DELETE` (6) `> a` (1) here
  though `strcmp` would say `<`. Otherwise — a string constant or an
  embedded function — the order is the lexicographic one of `strcmp`, e.g.,
  `http.method < 'HEAD'`;
- a string with a number is an error: `compile_rule` refuses the rule, e.g.,
  `(http.method < 5)` or `(http.method < (udp.len - 8))`. The one exception is
  `proto.att == 0` and `proto.att != 0` on a string attribute: the presence
  test of the attribute, e.g., `(ip.src != 0)`;
- the return type of an embedded `#function` is not known to `compile_rule`:
  it decides nothing, so a function call is compared as a string unless
  another operand is a number, e.g., `(#is_exist(dicom.pdu_type) >= 0)`.

# 5. Default values

In the XML file of a rule, if an attribute is absent then its value is set by default:

- `property`, `operator`:
   + `value` : `COMPUTE` (=> only one `<event>` is required. Thus `delay_min` and `delay_max` must be 0)
   + `delay_units`: `s`
   + `delay_min`: 0
   + `delay_max`: 0
   
An example of `COMPUTE`rule:

```XML
<property property_id="11" type_property="EVASION" 
    description="IP packet size incorrect">
    <event value="COMPUTE" event_id="1" 
           description="Packet size incorrect"
           boolean_expression="((meta.packet_len &lt; 34)"/>
</property>
```

 
# 6. Write a high performance rule
 
 To write a rule having a high performance one need to:
 
 - use only the proto.att in boolean expression when need. 

   - Please refer to the usage of function `is_exist` in section 2.3 to get an example.
   - TCP flag attributes (`tcp.flags`, `tcp.fin`, `tcp.syn`, `tcp.rst`, `tcp.psh`, `tcp.ack`, `tcp.urg`, `tcp.ece`, `tcp.cwr`) are present in every TCP packet, also when their value is 0, so a rule can test, e.g., `(tcp.flags == 0)` (TCP NULL scan, rule 42) or `(tcp.ack == 0)`.
   
     Up to version 1.2.20, MMT-Security dropped these attributes when their value was 0, so such tests never matched, and adding `(tcp.rst == 1)` to an expression made MMT-Security skip it on the packets without RST. This is no longer the case: write `(tcp.flags == 4)` rather than `((tcp.flags == 4) && (tcp.rst == 1))`.

 - reduce `delay_max` of a rule to a suitable value. 

 	When having a higher value of `delay_max` MMT-Security creates more rule instances to correlate different events of different packets. When `delay_max` is zero, the rule is call simple rule, MMT-Security verifies the rule and gives verdict immediately without creating any rule instances. A simple rule is verified much faster than a complex one that has non-zero `delay_max`.
 	
 	At 10Gbps, MMT-Security can verify 12400 simple rules or 600 complex rules.
 
 - optimize implementation of embedded functions.

	 - The embedded functions are called each time their boolean expressions are verified. Consequently, rather than initialize something, for example, connection to database, inside these functions, one can do such a task, only once, inside function `on_load` then store the connection into a static local variable that will be used inside the embedded functions.
	
	 - alway use embedded function with `static inline` keyword. For more information about advantage of `inline`, please refer to document of gcc: [An Inline Function is As Fast As a Macro](https://gcc.gnu.org/onlinedocs/gcc/Inline.html)

# 7. Rules on a protocol plugin

A rule can use the attributes of a protocol that an MMT-DPI plugin adds (a `.so` in the MMT-DPI plugin folder, for example one built with [mmt-plugin-generator](https://github.com/Montimage/mmt-plugin-generator)). Three things differ from rules on built-in protocols:

1. **The plugin must be installed when mmt-security is built.** mmt-security does not look protocols up at run time: `make gen_dpi` writes `src/dpi/mmt_dpi.h` from the protocols MMT-DPI loads at build time, and `compile_rule`, the library and the probe use that table. Install the plugin into the MMT-DPI plugin folder, then run `make clean-all && make -j1 && make install` (`clean-all` removes the old header). Without it, `compile_rule` stops with `Protocol <name> has not implemented yet`. The probe must load the same plugin at run time, since the ids in the table are the plugin's. `src/dpi/mmt_dpi.h` is tracked in git: `make clean-all` deletes it and `make` writes it again with the plugin's protocols, so `git status` then shows it modified (plain `make` also writes it again when the MMT-DPI folder is newer than the file). Do not commit it (`git checkout src/dpi/mmt_dpi.h` restores the stock table).
2. **Use the protocol name the plugin registers, as is.** Names are case-sensitive in rules. mmt-plugin-generator registers a plugin's protocol under its label in upper case, so the label `ocpp_example` gives `OCPP_EXAMPLE.action`. `./rule_info` on the compiled rule lists the resolved `proto.att (proto_id.att_id)`.
3. **Such rules are not compiled by default.** `make sample_rules` and `make deb` compile only `rules/*.xml`, and a stock build has no plugin protocols. Rules on plugins are kept in `rules/properties_all/` and compiled by hand:

```sh
./compile_rule rules/230.ocpp_heartbeat_flood.so rules/properties_all/230.ocpp_heartbeat_flood.xml
```

Example: rules 230 and 231 use the OCPP 1.6-J plugin `ocpp_example` (mmt-plugin-generator `examples/ocpp`):

| Rule | Detects | Settings (environment) |
|---|---|---|
| `230.ocpp_heartbeat_flood.xml` | a charge point session (`ip.src`, `tcp.src_port`) sending more than LIMIT Heartbeat CALLs within WINDOW seconds; reported once per window | `MMT_SEC_OCPP_HEARTBEAT_LIMIT` (10), `MMT_SEC_OCPP_HEARTBEAT_WINDOW_S` (10) |
| `231.ocpp_charging_limit.xml` | a SetChargingProfile CALL whose first limit is above the site maximum | `MMT_SEC_OCPP_MAX_CURRENT_A` (32), `MMT_SEC_OCPP_MAX_POWER_W` (22000) |

The settings are read by the rule's `on_load()`. The engine finds `on_load` and `on_unload` with `dlsym()`, so they must not be `static` (a `static` hook is never called and its settings are ignored); `make check` runs `check/check-rule-hooks.sh`, which fails on a rule XML that defines either as `static`.

Detection limits:

- Rule 230 counts per TCP session (`ip.src`, `tcp.src_port`): a flood spread over many connections, with at most LIMIT Heartbeats on each, is not flagged.
- Rule 230's window is in whole seconds: it starts at the whole second of a session's first Heartbeat (`meta.utime`'s `tv_sec`) and a Heartbeat whose second is WINDOW or more later starts the next one, so a window lasts between WINDOW - 1 and WINDOW seconds from its first Heartbeat (about 9 to 10 s at the default).
- Rule 231 checks only the first `chargingSchedulePeriod` (the plugin's `charging_limit_x10`): a SetChargingProfile whose first period is within the maximum and a later one above it is not flagged.

Both rules also reference `ip.src`, `ip.dst`, `tcp.src_port` and `tcp.dest_port` in their event (`(ip.src != ip.dst)`, `(tcp.dest_port > 0)`, the usual idiom of the sample rules), so that each alert carries the two endpoints; an alert only contains the attributes its event uses, and a consumer such as a SOAR needs the addresses to attribute or block. The rules therefore match OCPP over IPv4/TCP.

With mmt-probe, `security.ignore-remain-flow = true` (the default) skips every rule on the rest of a flow once any rule has raised an alert on it. On a flood where a TCP-level rule (for example 56, SYN flooding) fires first on each connection, rule 230 is then never evaluated; set it to `false`, or exclude those rules, where application-level alerts matter.

Synthetic captures in `check/pcap-plugin/` (written by `check/pcap-plugin/gen_ocpp_pcaps.py`, scapy) check both rules, at the defaults and with each setting, against `check/pcap-plugin/cases` and `check/pcap-plugin/expect/`. `make check` cannot run them, since a stock build cannot compile these rules. With the plugin installed in the MMT-DPI plugin folder:

```sh
make clean-all && make -j1
check/pcap-plugin/run.sh        # compiles rules/*.xml, 230 and 231, runs every case
git checkout src/dpi/mmt_dpi.h  # back to the stock protocol table
```

| Capture | Content | Alerts at the defaults |
|---|---|---|
| `ocpp_230_heartbeat_flood` | CP A: 30 Heartbeats every 250 ms; CP B: 60 every 250 ms (two windows); CP C: 5 every 60 s | 230 × 3 (A once, B twice) |
| `ocpp_231_charging_limit` | SetChargingProfile at 10, 90, 32, 32.1 and 16 A and at 22000 and 30000 W, each answered | 231 × 3 (90 A, 32.1 A, 30000 W) |
| `ocpp_benign` | a normal CP over 10 min (Boot, Authorize, StatusNotification, a Heartbeat every 60 s, SetChargingProfile at 0, 10, 16 and 32 A and at 11000 and 22000 W); a CP at exactly 10 Heartbeats in 2.25 s; a CP at 1 Heartbeat per second for 20 s | none, from any rule |

These pass with mmt-dpi 1.10.3 (`6a0afb46`) and the plugin from mmt-plugin-generator `f8ade97` (`examples/ocpp`, built with the generator's compile and link flags against the 1.10.3 headers).

Measured on the Federated OCPP 1.6 Intrusion Detection Dataset (Zenodo record 14887131, CC-BY-4.0) with mmt-dpi 1.10.2 (`8e6faf4`), this branch's base (`a78a4fd`), mmt-probe `fbf0c3d` and the plugin from mmt-plugin-generator `220adc1` (retested at `73aa717` with mmt-dpi `main` `b89d409`, mmt-probe `1e00441` and the plugin from mmt-plugin-generator `f8ade97`: same alerts per rule):

- Attack 3 (Heartbeat flooding, 100 fake charge points): rule 230 flags all 100 sessions, on the 11th Heartbeat (2.5 s after each session's first one), and no other session. Normal sessions in attacks 1 and 2 peak at 2 Heartbeats per 10 s.
- Attack 1 (SetChargingProfile changed to 90 A by a MiTM): rule 231 flags 3 228 of the 3 229 manipulated messages (first copies; retransmitted copies are flagged again) and none of the 3 488 genuine 10 A ones; its first alert is on the first manipulated message.
