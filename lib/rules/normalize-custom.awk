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

function valid_domain(value, labels, n, i) {
  if (value == "" || length(value) > 253 || value ~ /\.\./ || value ~ /[*?]/) return 0
  n = split(value, labels, ".")
  for (i = 1; i <= n; i++) {
    if (labels[i] == "" || length(labels[i]) > 63 || labels[i] !~ /^[A-Za-z0-9-]+$/ || labels[i] ~ /^-/ || labels[i] ~ /-$/) return 0
  }
  return 1
}

function safe_domain(value) {
  value = tolower(value)
  sub(/\.$/, "", value)
  if (!valid_domain(value) || value ~ /^[0-9.]+$/ || value ~ /(^|\.)localhost$/ || value == "ip6-allnodes" || value == "ip6-localhost") return ""
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
  sub(/\r$/, "", line)
  if (NR == 1) {
    bom = sprintf("%c%c%c", 239, 187, 191)
    if (substr(line, 1, 3) == bom) line = substr(line, 4)
  }
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
  if (line == "" || line ~ /^[!#]/ || line ~ /^\[(Adblock Plus|AdGuard)( [^]]*)?\]$/) next

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
  } else if (substr(rule, 1, 1) == "|") {
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
    if (rule ~ /\^\|$/) {
      sub(/\^\|$/, "", rule)
    } else if (rule ~ /\^$/) {
      sub(/\^$/, "", rule)
    } else {
      unsupported()
      next
    }
    if (action == "A" ? emit_allow(rule) : emit_block(rule)) next
    unsupported()
    next
  }

  if (line ~ /##|#@#|#\?#|#%#|#[$]#/) {
    unsupported()
    next
  }
  sub(/[[:space:]]+#.*/, "", line)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
  if (line == "") next
  n = split(line, fields, /[[:space:]]+/)
  if (ipv4(fields[1]) || ipv6(fields[1])) {
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
