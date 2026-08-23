# 这些查表和常量在 BEGIN 里建好，主循环里就不必反复做字符串比较或重算 BOM。
BEGIN {
  BOM = sprintf("%c%c%c", 239, 187, 191)
  WS[" "] = 1; WS["\t"] = 1; WS["\v"] = 1; WS["\f"] = 1; WS["\r"] = 1
  DIGIT["0"] = 1; DIGIT["1"] = 1; DIGIT["2"] = 1; DIGIT["3"] = 1; DIGIT["4"] = 1
  DIGIT["5"] = 1; DIGIT["6"] = 1; DIGIT["7"] = 1; DIGIT["8"] = 1; DIGIT["9"] = 1
  SPECIAL["localhost"] = 1; SPECIAL["ip6-allnodes"] = 1; SPECIAL["ip6-localhost"] = 1
}

function ipv4(value, parts, n, i) {
  n = split(value, parts, ".")
  if (n != 4) return 0
  for (i = 1; i <= 4; i++) {
    if (parts[i] !~ /^[0-9]+$/ || parts[i] > 255) return 0
  }
  return 1
}

function ipv6(value) {
  return value ~ /^[0-9A-Fa-f:]+$/ && value ~ /:/ && value !~ /:::/
}

# hosts 段的第一列几乎总是那几个固定 IP，缓存判定结果能省掉每行的正则匹配。
# 「只有域名」的列表里第一列全都不同，所以缓存必须有上限，否则会白吃几十万条内存。
function ip_kind(value, kind) {
  if (value in IPKIND) return IPKIND[value]
  kind = (ipv4(value) || ipv6(value)) ? 1 : 0
  if (IPKIND_N < 64) {
    IPKIND[value] = kind
    IPKIND_N++
  }
  return kind
}

# 逐个标签跑正则太慢：先用一次字符集匹配挡掉非法字符，剩下的「标签非空、
# 不以连字符开头或结尾」都能用 index 判断首尾与 ".." ".-" "-." 三种组合等价表达。
function valid_domain(value, len, c1, cn, labels, n, i) {
  len = length(value)
  if (len == 0 || len > 253) return 0
  if (value ~ /[^A-Za-z0-9.-]/) return 0
  c1 = substr(value, 1, 1)
  cn = substr(value, len)
  if (c1 == "." || c1 == "-" || cn == "." || cn == "-") return 0
  if (index(value, "..") || index(value, ".-") || index(value, "-.")) return 0
  # 走到这里字符集只剩字母、数字、点和连字符，所以「没有字母也没有连字符」就等于纯数字域名。
  if ((c1 in DIGIT) && value !~ /[A-Za-z-]/) return 0
  # 整个域名不超过 63 个字符时，单个标签不可能超长，可以跳过拆分。
  if (len > 63) {
    n = split(value, labels, ".")
    for (i = 1; i <= n; i++) if (length(labels[i]) > 63) return 0
  }
  return 1
}

function safe_domain(value, len) {
  value = tolower(value)
  len = length(value)
  if (len && substr(value, len) == ".") {
    value = substr(value, 1, len - 1)
    len--
  }
  if (!valid_domain(value)) return ""
  if (value in SPECIAL) return ""
  if (len >= 10 && substr(value, len - 9) == ".localhost") return ""
  return value
}

function emit_block(domain) {
  domain = safe_domain(domain)
  if (domain != "") {
    print "B\t" domain "\t0.0.0.0"
    return 1
  }
  return 0
}

function emit_allow(domain) {
  domain = safe_domain(domain)
  if (domain != "") {
    print "A\t" domain
    return 1
  }
  return 0
}

function unsupported() {
  print "S\tunsupported"
}

function safe_options(value, options, n, i, option) {
  if (value == "") return 0
  n = split(value, options, ",")
  for (i = 1; i <= n; i++) {
    option = tolower(options[i])
    if (option != "important" && option != "match-case") return 0
  }
  return 1
}

{
  line = $0
  len = length(line)
  if (len && substr(line, len) == "\r") {
    line = substr(line, 1, len - 1)
    len--
  }
  if (NR == 1 && substr(line, 1, 3) == BOM) {
    line = substr(line, 4)
    len -= 3
  }
  # 只有真的带首尾空白时才值得跑 gsub。
  if (len && ((substr(line, 1, 1) in WS) || (substr(line, len) in WS))) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    len = length(line)
  }
  if (len == 0) next
  head = substr(line, 1, 1)
  if (head == "!" || head == "#") next
  # 只有以 "[" 开头的行才可能是订阅头，其余行不必跑这条正则。
  if (head == "[" && line ~ /^\[(Adblock Plus|AdGuard)( [^]]*)?\]$/) next

  action = ""
  rule = line
  if (substr(rule, 1, 4) == "@@||") {
    action = "A"
    rule = substr(rule, 5)
  } else if (substr(rule, 1, 3) == "@@|") {
    action = "A"
    rule = substr(rule, 4)
  } else if (substr(rule, 1, 2) == "||") {
    action = "B"
    rule = substr(rule, 3)
  } else if (head == "|") {
    action = "B"
    rule = substr(rule, 2)
  }

  if (action != "") {
    options = ""
    option_start = index(rule, "$")
    if (option_start > 0) {
      options = substr(rule, option_start + 1)
      rule = substr(rule, 1, option_start - 1)
      if (!safe_options(options)) {
        unsupported()
        next
      }
    }
    rule_len = length(rule)
    if (rule_len >= 2 && substr(rule, rule_len - 1) == "^|") {
      rule = substr(rule, 1, rule_len - 2)
    } else if (rule_len >= 1 && substr(rule, rule_len) == "^") {
      rule = substr(rule, 1, rule_len - 1)
    } else {
      unsupported()
      next
    }
    if (action == "A" ? emit_allow(rule) : emit_block(rule)) next
    unsupported()
    next
  }

  # 元素隐藏等语法一定带 "#"，先用一次 index 挡掉，没有 "#" 的行就不必跑这两条正则。
  if (index(line, "#")) {
    if (line ~ /##|#@#|#\?#|#%#|#[$]#/) {
      unsupported()
      next
    }
    sub(/[[:space:]]+#.*/, "", line)
    len = length(line)
    if (len && ((substr(line, 1, 1) in WS) || (substr(line, len) in WS))) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      len = length(line)
    }
    if (len == 0) next
  }
  # 分隔符必须写成正则字面量：换成字符串会让 busybox awk 每次调用都重新编译，反而慢一倍。
  n = split(line, fields, /[[:space:]]+/)
  if (ip_kind(fields[1])) {
    start = 2
  } else if (n == 1) {
    start = 1
  } else {
    unsupported()
    next
  }

  emitted = 0
  for (i = start; i <= n; i++) emitted += emit_block(fields[i])
  if (!emitted) unsupported()
}