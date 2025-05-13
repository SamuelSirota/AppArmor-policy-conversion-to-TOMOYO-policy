import re
from typing import List, Dict, Tuple


def parse_policy_lines(policy_str: str) -> List[Tuple[str, str]]:
    """
    Parse lines like:
       /etc/gcrypt/random.conf r,
       /usr/lib{,32,64}/locale/**    mr,
       owner /home/*/.Private/** mrixwlk,
       /usr/bin/bzip2 rmCx -> &man_filter,
    into a list of (perm, path) tuples.
    """
    entries: List[Tuple[str, str]] = []
    for raw in policy_str.strip().splitlines():
        line = raw.strip().rstrip(",")  # drop trailing comma
        if not line or line.startswith("#"):
            continue
        # remove any "-> &profile" suffix

        line = re.sub(r"\s*->\s*&\w+$", "", line)

        # owner lines: "owner /path perm"

        if line.startswith("owner "):
            _, path, perms = line.split(None, 2)
        else:
            # normal: "/path/to/foo perms"

            parts = line.rsplit(maxsplit=1)
            if len(parts) != 2:
                continue
            path, perms = parts
        entries.append((perms, path))
    return entries


def expand_variables(path: str, variables: Dict[str, List[str]]) -> List[str]:
    var_re = re.compile(r"@{([^}]+)}")
    paths = [path]
    while True:
        new, did = [], False
        for p in paths:
            m = var_re.search(p)
            if not m:
                new.append(p)
                continue
            key = f"@{{{m.group(1)}}}"
            for val in variables.get(key, []):
                new.append(p[: m.start()] + val + p[m.end() :])
            did = True
        paths = new
        if not did:
            break
    return [re.sub(r"/{2,}", "/", p) for p in paths]


def expand_brace_expressions(pat: str) -> List[str]:
    m = re.search(r"\{([^{}]*)\}", pat)
    if not m:
        return [pat]
    pre, body, post = pat[: m.start()], m.group(1), pat[m.end() :]
    out = []
    for alt in body.split(","):
        out += expand_brace_expressions(pre + alt + post)
    return out


def expand_bracket_expressions(pat: str) -> List[str]:
    m = re.search(r"\[([^\]]+)\]", pat)
    if not m:
        return [pat]
    pre, content, post = pat[: m.start()], m.group(1), pat[m.end() :]
    chars = []
    i = 0
    while i < len(content):
        if i + 2 < len(content) and content[i + 1] == "-" and content[i + 2] != "]":
            for c in range(ord(content[i]), ord(content[i + 2]) + 1):
                chars.append(chr(c))
            i += 3
        else:
            chars.append(content[i])
            i += 1
    out = []
    for ch in chars:
        out += expand_bracket_expressions(pre + ch + post)
    return out


def flatten_policy_operations(
    policy_str: str,
    variables: Dict[str, List[str]] = None,
    aliases: Dict[str, str] = None,
) -> List[Tuple[str, str]]:
    """
    From the raw policy text, produce a flat list of (perm, path)
    with all @{} , brace and bracket patterns expanded—but leaving
    * and ** intact.
    """
    variables = variables or {}
    aliases = aliases or {}
    flat_ops: List[Tuple[str, str]] = []

    for perm, raw_path in parse_policy_lines(policy_str):
        # apply any simple prefix aliases

        for src, dst in aliases.items():
            if raw_path.startswith(src):
                raw_path = dst + raw_path[len(src) :]
                break
        # 1) variable expansion

        for v1 in expand_variables(raw_path, variables):
            # 2) brace expansion

            for v2 in expand_brace_expressions(v1):
                # 3) bracket expansion

                for v3 in expand_bracket_expressions(v2):
                    flat_ops.append((perm, v3))
    # dedupe

    return sorted(set(flat_ops), key=lambda x: (x[0], x[1]))


if __name__ == "__main__":
    policy_text = """
      /etc/gcrypt/random.conf r,
  /usr/etc/gcrypt/random.conf r,
  /proc/sys/crypto/fips_enabled r,
  /proc/sys/crypto/* r,
  /etc/crypto-policies/*/*.txt r,
  /usr/share/crypto-policies/*/*.txt r,
  /dev/log                       w,
  /dev/random                    r,
  /dev/urandom                   r,
  /run/uuidd/request           r,
  /var/run/uuidd/request           r,
  /etc/locale/**          r,
  /usr/etc/locale/**          r,
  /etc/locale.alias       r,
  /usr/etc/locale.alias       r,
  /etc/localtime          r,
  /usr/etc/localtime          r,
  /etc/writable/localtime        r,
  /usr/share/locale-bundle/**    r,
  /usr/share/locale-langpack/**  r,
  /usr/share/locale/**           r,
  /usr/share/**/locale/**        r,
  /usr/share/zoneinfo/           r,
  /usr/share/zoneinfo/**         r,
  /usr/share/X11/locale/**       r,
  /run/systemd/journal/dev-log w,
  /var/run/systemd/journal/dev-log w,
  /run/systemd/journal/socket  w,
  /var/run/systemd/journal/socket  w,
  /run/systemd/journal/stdout  rw,
  /var/run/systemd/journal/stdout  rw,
  /usr/lib{,32,64}/locale/**             mr,
  /usr/lib{,32,64}/gconv/*.so            mr,
  /usr/lib{,32,64}/gconv/gconv-modules*  mr,
  /usr/lib/*-linux-gnu*/gconv/*.so           mr,
  /usr/lib/*-linux-gnu*/gconv/gconv-modules* mr,
  /etc/bindresvport.blacklist    r,
  /usr/etc/bindresvport.blacklist    r,
  /etc/ld.so.cache               mr,
  /usr/etc/ld.so.cache               mr,
  /etc//ld.so.conf                r,
  /usr/etc/ld.so.conf                r,
  /etc/ld.so.conf.d/{,*.conf}    r,
  /usr/etc/ld.so.conf.d/{,*.conf}    r,
  /etc/ld.so.preload             r,
  /usr/etc/ld.so.preload             r,
  /{usr/,}lib{,32,64}/ld{,32,64}-*.so   mr,
  /{usr/,}lib/*-linux-gnu*/ld{,32,64}-*.so    mr,
  /{usr/,}lib/tls/i686/{cmov,nosegneg}/ld-*.so     mr,
  /{usr/,}lib/i386-linux-gnu/tls/i686/{cmov,nosegneg}/ld-*.so     mr,
  /opt/*-linux-uclibc/lib/ld-uClibc*so* mr,
  /{usr/,}lib{,32,64}/**                r,
  /{usr/,}lib{,32,64}/**.so*       mr,
  /{usr/,}lib/*-linux-gnu*/**            r,
  /{usr/,}lib/*-linux-gnu*/**.so*   mr,
  /{usr/,}lib/tls/i686/{cmov,nosegneg}/*.so*    mr,
  /{usr/,}lib/i386-linux-gnu/tls/i686/{cmov,nosegneg}/*.so*    mr,
  /{usr/,}lib{,32,64}/.lib*.so*.hmac      r,
  /{usr/,}lib/*-linux-gnu*/.lib*.so*.hmac r,
  /dev/null                      rw,
  /dev/zero                      rw,
  /dev/full                      rw,
  /proc/sys/kernel/version     r,
  /proc/sys/kernel/ngroups_max r,
  /proc/meminfo                r,
  /proc/stat                   r,
  /proc/cpuinfo                r,
  /sys/devices/system/cpu/       r,
  /sys/devices/system/cpu/online r,
  /proc/@{pid}/{maps,auxv,status} r,
  /proc/sys/crypto/*           r,
  /usr/share/common-licenses/**  r,
  /proc/filesystems            r,
  /proc/sys/vm/overcommit_memory r,
  /proc/sys/kernel/cap_last_cap r,

  owner /home/*/.Private/ r,
  owner /root/.Private/ r,
  owner /home/*/.Private/** mrixwlk,
  owner /root/.Private/** mrixwlk,
  owner /home/.ecryptfs/*/.Private/ r,
  owner /home/.ecryptfs/*/.Private/** mrixwlk,

  /usr/bin/eqn rmCx -> &man_groff,
  /usr/bin/grap rmCx -> &man_groff,
  /usr/bin/pic rmCx -> &man_groff,
  /usr/bin/preconv rmCx -> &man_groff,
  /usr/bin/refer rmCx -> &man_groff,
  /usr/bin/tbl rmCx -> &man_groff,
  /usr/bin/troff rmCx -> &man_groff,
  /usr/bin/vgrind rmCx -> &man_groff,

  /{,usr/}bin/bzip2 rmCx -> &man_filter,
  /{,usr/}bin/gzip rmCx -> &man_filter,
  /usr/bin/col rmCx -> &man_filter,
  /usr/bin/compress rmCx -> &man_filter,
  /usr/bin/iconv rmCx -> &man_filter,
  /usr/bin/lzip.lzip rmCx -> &man_filter,
  /usr/bin/tr rmCx -> &man_filter,
  /usr/bin/xz rmCx -> &man_filter,
  /** mrixwlk,
    """

    variables = {"@{pid}": [str(i) for i in range(1, 10)]}

    flat = flatten_policy_operations(policy_text, variables)

    output_path = "man_with_flat_paths.txt"
    with open(output_path, "w") as f:
        for perm, path in flat:
            f.write(f"{path:<60} {perm},\n")
    print(f"Generated {len(flat)} entries in {output_path}")
