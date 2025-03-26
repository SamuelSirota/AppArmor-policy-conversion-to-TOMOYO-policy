# AppArmor BNF

- [x] PROFILE FILE = ( [ PREAMBLE ] [ PROFILE ] )*

- [x] PREAMBLE = ( COMMENT | VARIABLE ASSIGNMENT | ALIAS RULE | INCLUDE | ABI )*
    Variable assignment and alias rules must come before the profile.

- [x] VARIABLE ASSIGNMENT = VARIABLE ('=' | '+=') (space separated values)

- [x] VARIABLE = '@{' ALPHA [ ( ALPHANUMERIC | '_' ) ... ] '}'

- [x] ALIAS RULE = 'alias' ABS PATH '->' REWRITTEN ABS PATH ','

- [x] INCLUDE = ( '#include' | 'include' ) [ 'if exists' ] ( ABS PATH | MAGIC PATH )

- [x] ABI = ( 'abi' ) ( ABS PATH | MAGIC PATH ) ','

ABS PATH = '"' path '"' (the path is passed to open(2))

- [x] MAGIC PATH = '<' relative path '>'
    The path is relative to /etc/apparmor.d/.

- [x] COMMENT = '#' TEXT [ '\r' ] '\n'

-[x] TEXT = any characters

- [x] PROFILE = ( PROFILE HEAD ) [ ATTACHMENT SPECIFICATION ] [ PROFILE FLAG CONDS ] '{' ( RULES )* '}'

- [x] PROFILE HEAD = [ 'profile' ] FILEGLOB | 'profile' PROFILE NAME

- [x] PROFILE NAME ( UNQUOTED PROFILE NAME | QUOTED PROFILE NAME )

- [x] QUOTED PROFILE NAME = '"' UNQUOTED PROFILE NAME '"'

- [x] UNQUOTED PROFILE NAME = (must start with alphanumeric character (after variable expansion), or '/'
AARE have special meanings; see below. May include VARIABLE. Rules with embedded spaces or tabs must
be quoted.)

- [x] ATTACHMENT SPECIFICATION = FILEGLOB

- [x] PROFILE FLAG CONDS =  [ 'flags=' ] '(' comma or white space separated list of PROFILE FLAGS ')'

- [x] PROFILE FLAGS = 'complain' | 'audit' | 'enforce' | 'mediate_deleted' | 'attach_disconnected' |
'chroot_relative'

- [x] RULES = [ ( LINE RULES | COMMA RULES ',' | BLOCK RULES ) ]

- [x] LINE RULES = ( COMMENT | INCLUDE ) [ '\r' ] '\n'

COMMA RULES = ( CAPABILITY RULE | NETWORK RULE | MOUNT RULE | PIVOT ROOT RULE | UNIX RULE | FILE RULE
| LINK RULE | CHANGE_PROFILE RULE | RLIMIT RULE | DBUS RULE | MQUEUE RULE )

BLOCK RULES = ( SUBPROFILE | HAT | QUALIFIER BLOCK )

- [x] SUBPROFILE = 'profile' PROFILE NAME [ ATTACHMENT SPECIFICATION ] [ PROFILE FLAG CONDS ] '{' ( RULES
)* '}'

- [x] HAT = ('hat' | '^') HATNAME [ PROFILE FLAG CONDS ] '{' ( RULES )* '}'

- [x] HATNAME = (must start with alphanumeric character. See aa_change_hat(2) for a description of how this
"hat" is used. If '^' is used to start a hat then there is no space between the '^' and HATNAME)

QUALIFIER BLOCK = QUALIFIERS BLOCK

- [x] ACCESS TYPE = ( 'allow' | 'deny' )

- [x] QUALIFIERS = [ 'audit' ] [ ACCESS TYPE ]

- [x] CAPABILITY RULE = [ QUALIFIERS ] 'capability' [ CAPABILITY LIST ]

- [x] CAPABILITY LIST = ( CAPABILITY )+

- [x] CAPABILITY = (lowercase capability name without 'CAP_' prefix; see capabilities(7))

- [x] NETWORK RULE = [ QUALIFIERS ] 'network' [ DOMAIN ] [ TYPE | PROTOCOL ]

- [x] DOMAIN = ( 'unix' | 'inet' | 'ax25' | 'ipx' | 'appletalk' | 'netrom' | 'bridge' | 'atmpvc' | 'x25' |
'inet6' | 'rose' | 'netbeui' | 'security' | 'key' | 'netlink' | 'packet' | 'ash' | 'econet' |
'atmsvc' | 'rds' | 'sna' | 'irda' | 'pppox' | 'wanpipe' | 'llc' | 'ib' | 'mpls' | 'can' | 'tipc' |
'bluetooth' | 'iucv' | 'rxrpc' | 'isdn' | 'phonet' | 'ieee802154' | 'caif' | 'alg' | 'nfc' | 'vsock'
| 'kcm' | 'qipcrtr' | 'smc' | 'xdp' ) ','

- [x] TYPE = ( 'stream' | 'dgram' | 'seqpacket' |  'rdm' | 'raw' | 'packet' )

- [x] PROTOCOL = ( 'tcp' | 'udp' | 'icmp' )

MOUNT RULE = ( MOUNT | REMOUNT | UMOUNT )

MOUNT = [ QUALIFIERS ] 'mount' [ MOUNT CONDITIONS ] [ SOURCE FILEGLOB ] [ '->' [ MOUNTPOINT FILEGLOB
]

REMOUNT = [ QUALIFIERS ] 'remount' [ MOUNT CONDITIONS ] MOUNTPOINT FILEGLOB

UMOUNT = [ QUALIFIERS ] 'umount' [ MOUNT CONDITIONS ] MOUNTPOINT FILEGLOB

MOUNT CONDITIONS = [ ( 'fstype' | 'vfstype' ) ( '=' | 'in' ) MOUNT FSTYPE EXPRESSION ] [ 'options' (
'=' | 'in' ) MOUNT FLAGS EXPRESSION ]

MOUNT FSTYPE EXPRESSION = ( MOUNT FSTYPE LIST | MOUNT EXPRESSION )

MOUNT FSTYPE LIST = Comma separated list of valid filesystem and virtual filesystem types (eg ext4,
debugfs, devfs, etc)

MOUNT FLAGS EXPRESSION = ( MOUNT FLAGS LIST | MOUNT EXPRESSION )

MOUNT FLAGS LIST = Comma separated list of MOUNT FLAGS.

MOUNT FLAGS = ( 'ro' | 'rw' | 'nosuid' | 'suid' | 'nodev' | 'dev' | 'noexec' | 'exec' | 'sync' |
'async' | 'remount' | 'mand' | 'nomand' | 'dirsync' | 'noatime' | 'atime' | 'nodiratime' | 'diratime'
| 'bind' | 'rbind' | 'move' | 'verbose' | 'silent' | 'loud' | 'acl' | 'noacl' | 'unbindable' |
'runbindable' | 'private' | 'rprivate' | 'slave' | 'rslave' | 'shared' | 'rshared' | 'relatime' |
'norelatime' | 'iversion' | 'noiversion' | 'strictatime' | 'nostrictatime' | 'lazytime' |
'nolazytime' | 'nouser' | 'user' | 'symfollow' | 'nosymfollow' )

MOUNT EXPRESSION = ( ALPHANUMERIC | AARE ) ...

MQUEUE_RULE = [ QUALIFIERS ] 'mqueue' [ MQUEUE ACCESS PERMISSIONS ] [ MQUEUE TYPE ] [ MQUEUE LABEL ]
[ MQUEUE NAME ]

MQUEUE ACCESS PERMISSIONS = MQUEUE ACCESS | MQUEUE ACCESS LIST

MQUEUE ACCESS LIST = '(' Comma or space separated list of MQUEUE ACCESS ')'

MQUEUE ACCESS = ( 'r' | 'w' | 'rw' | 'read' | 'write' | 'create' | 'open' | 'delete' | 'getattr' |
'setattr' )

MQUEUE TYPE = 'type' '=' ( 'posix' | 'sysv' )

MQUEUE LABEL = 'label' '=' '(' '"' AARE '"' | AARE ')'

MQUEUE NAME = AARE

PIVOT ROOT RULE = [ QUALIFIERS ] pivot_root [ oldroot=OLD PUT FILEGLOB ] [ NEW ROOT FILEGLOB ] [ '->'
PROFILE NAME ]

SOURCE FILEGLOB = FILEGLOB

MOUNTPOINT FILEGLOB = FILEGLOB

OLD PUT FILEGLOB = FILEGLOB

PTRACE_RULE = [ QUALIFIERS ] 'ptrace' [ PTRACE ACCESS PERMISSIONS ] [ PTRACE PEER ]

PTRACE ACCESS PERMISSIONS = PTRACE ACCESS | PTRACE ACCESS LIST

PTRACE ACCESS LIST = '(' Comma or space separated list of PTRACE ACCESS ')'

PTRACE ACCESS = ( 'r' | 'w' | 'rw' | 'read' | 'readby' | 'trace' | 'tracedby' )

PTRACE PEER = 'peer' '=' AARE

SIGNAL_RULE = [ QUALIFIERS ] 'signal' [ SIGNAL ACCESS PERMISSIONS ] [ SIGNAL SET ] [ SIGNAL PEER ]

SIGNAL ACCESS PERMISSIONS = SIGNAL ACCESS | SIGNAL ACCESS LIST

SIGNAL ACCESS LIST = '(' Comma or space separated list of SIGNAL ACCESS ')'

SIGNAL ACCESS = ( 'r' | 'w' | 'rw' | 'read' | 'write' | 'send' | 'receive' )

SIGNAL SET = 'set' '=' '(' SIGNAL LIST ')'

SIGNAL LIST = Comma or space separated list of SIGNALS

SIGNALS = ( 'hup' | 'int' | 'quit' | 'ill' | 'trap' | 'abrt' | 'bus' | 'fpe' | 'kill' | 'usr1' |
'segv' | 'usr2' | 'pipe' | 'alrm' | 'term' | 'stkflt' | 'chld' | 'cont' | 'stop' | 'stp' | 'ttin' |
'ttou' | 'urg' | 'xcpu' | 'xfsz' | 'vtalrm' | 'prof' | 'winch' | 'io' | 'pwr' | 'sys' | 'emt' |
'exists' | 'rtmin+0' ... 'rtmin+32' )

SIGNAL PEER = 'peer' '=' AARE

DBUS RULE = ( DBUS MESSAGE RULE | DBUS SERVICE RULE | DBUS EAVESDROP RULE | DBUS COMBINED RULE )

DBUS MESSAGE RULE = [ QUALIFIERS ] 'dbus' [ DBUS ACCESS EXPRESSION ] [ DBUS BUS ] [ DBUS PATH ] [
DBUS INTERFACE ] [ DBUS MEMBER ] [ DBUS PEER ]

DBUS SERVICE RULE = [ QUALIFIERS ] 'dbus' [ DBUS ACCESS EXPRESSION ] [ DBUS BUS ] [ DBUS NAME ]

DBUS EAVESDROP RULE = [ QUALIFIERS ] 'dbus' [ DBUS ACCESS EXPRESSION ] [ DBUS BUS ]

DBUS COMBINED RULE = [ QUALIFIERS ] 'dbus' [ DBUS ACCESS EXPRESSION ] [ DBUS BUS ]

DBUS ACCESS EXPRESSION = ( DBUS ACCESS | '(' DBUS ACCESS LIST ')' )

DBUS BUS = 'bus' '=' '(' 'system' | 'session' | '"' AARE '"' | AARE ')'

DBUS PATH = 'path' '=' '(' '"' AARE '"' | AARE ')'

DBUS INTERFACE = 'interface' '=' '(' '"' AARE '"' | AARE ')'

DBUS MEMBER = 'member' '=' '(' '"' AARE '"' | AARE ')'

DBUS PEER = 'peer' '=' '(' [ DBUS NAME ] [ DBUS LABEL ] ')'

DBUS NAME = 'name' '=' '(' '"' AARE '"' | AARE ')'

DBUS LABEL = 'label' '=' '(' '"' AARE '"' | AARE ')'

DBUS ACCESS LIST = Comma separated list of DBUS ACCESS

DBUS ACCESS = ( 'send' | 'receive' | 'bind' | 'eavesdrop' | 'r' | 'read' | 'w' | 'write' | 'rw' )
    Some accesses are incompatible with some rules; see below.

AARE = ?*[]{}^
    See below for meanings.

UNIX RULE = [ QUALIFIERS ] 'unix' [ UNIX ACCESS EXPR ] [ UNIX RULE CONDS ] [ UNIX LOCAL EXPR ] [ UNIX
PEER EXPR ]

UNIX ACCESS EXPR = ( UNIX ACCESS | UNIX ACCESS LIST )

UNIX ACCESS = ( 'create' | 'bind' | 'listen' | 'accept' | 'connect' | 'shutdown' | 'getattr' |
'setattr' | 'getopt' | 'setopt' | 'send' | 'receive' | 'r' | 'w' | 'rw' )
    Some access modes are incompatible with some rules or require additional parameters.

UNIX ACCESS LIST = '(' UNIX ACCESS ( [','] UNIX ACCESS )* ')'

UNIX RULE CONDS = ( TYPE COND | PROTO COND )
    Each cond can appear at most once.

TYPE COND = 'type' '='  ( AARE | '(' ( '"' AARE '"' | AARE )+ ')' )

PROTO COND = 'protocol' '='  ( AARE | '(' ( '"' AARE '"' | AARE )+ ')' )

UNIX LOCAL EXPR = ( UNIX ADDRESS COND | UNIX LABEL COND | UNIX ATTR COND | UNIX OPT COND )*
    Each cond can appear at most once.

UNIX PEER EXPR = 'peer' '=' ( UNIX ADDRESS COND | UNIX LABEL COND )+
    Each cond can appear at most once.

UNIX ADDRESS COND 'addr' '=' ( AARE | '(' '"' AARE '"' | AARE ')' )

UNIX LABEL COND 'label' '=' ( AARE | '(' '"' AARE '"' | AARE ')' )

UNIX ATTR COND 'attr' '=' ( AARE | '(' '"' AARE '"' | AARE ')' )

UNIX OPT COND 'opt' '=' ( AARE | '(' '"' AARE '"' | AARE ')' )

RLIMIT RULE = 'set' 'rlimit' [RLIMIT '<=' RLIMIT VALUE ]

RLIMIT = ( 'cpu' | 'fsize' | 'data' | 'stack' | 'core' | 'rss' | 'nofile' | 'ofile' | 'as' | 'nproc'
| 'memlock' | 'locks' | 'sigpending' | 'msgqueue' | 'nice' | 'rtprio' | 'rttime' )

RLIMIT VALUE = ( RLIMIT SIZE | RLIMIT NUMBER | RLIMIT TIME | RLIMIT NICE )

RLIMIT SIZE = NUMBER ( 'K' | 'M' | 'G' )
    Only applies to RLIMIT of 'fsize', 'data', 'stack', 'core', 'rss', 'as', 'memlock', 'msgqueue'.

RLIMIT NUMBER = number from 0 to max rlimit value.
    Only applies to RLIMIT of 'ofile', 'nofile', 'locks', 'sigpending', 'nproc', 'rtprio'.

RLIMIT TIME = NUMBER ( 'us' | 'microsecond' | 'microseconds' | 'ms' | 'millisecond' | 'milliseconds'
| 's' | 'sec' | 'second' | 'seconds' | 'min' | 'minute' | 'minutes' | 'h' | 'hour' | 'hours' | 'd' |
'day' | 'days' | 'week' | 'weeks' )
    Only applies to RLIMIT of 'cpu' and 'rttime'. RLIMIT 'cpu' only allows units >= 'seconds'.

RLIMIT NICE = a number between -20 and 19.
    Only applies to RLIMIT of 'nice'.

FILE RULE = [ QUALIFIERS ] [ 'owner' ] ( 'file' | [ 'file' ] ( FILEGLOB ACCESS  | ACCESS FILEGLOB ) [
'->' EXEC TARGET ] )

FILEGLOB = ( QUOTED FILEGLOB | UNQUOTED FILEGLOB )

QUOTED FILEGLOB = '"' UNQUOTED FILEGLOB '"'

UNQUOTED FILEGLOB = (must start with '/' (after variable expansion), AARE have special meanings; see
below. May include VARIABLE. Rules with embedded spaces or tabs must be quoted. Rules must end with
'/' to apply to directories.)

ACCESS = ( 'r' | 'w' | 'a' | 'l' | 'k' | 'm' | EXEC TRANSITION )+  (not all combinations are allowed;
see below.)

EXEC TRANSITION =  ( 'ix' | 'ux' | 'Ux' | 'px' | 'Px' | 'cx' | 'Cx' | 'pix' | 'Pix' | 'cix' | 'Cix' |
'pux' | 'PUx' | 'cux' | 'CUx' | 'x' )
    A bare 'x' is only allowed in rules with the deny qualifier, everything else only without the deny
qualifier.

EXEC TARGET = name
    Requires EXEC TRANSITION specified.

LINK RULE = QUALIFIERS [ 'owner' ] 'link' [ 'subset' ] FILEGLOB '->' FILEGLOB

ALPHA = ('a', 'b', 'c', ... 'z', 'A', 'B', ... 'Z')

ALPHANUMERIC = ('0', '1', '2', ... '9', 'a', 'b', 'c', ... 'z', 'A', 'B', ... 'Z')

CHANGE_PROFILE RULE = 'change_profile' [ [ EXEC MODE ] EXEC COND ] [ '->' PROFILE NAME ]

EXEC_MODE = ( 'safe' | 'unsafe' )

EXEC COND = FILEGLOB