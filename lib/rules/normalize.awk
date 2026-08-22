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
  if (value == "" || length(value) > 253 || value ~ /^[0-9.]+$/ || value ~ /\.\./ || value ~ /[*?]/) return 0
  n = split(value, labels, ".")
  for (i = 1; i <= n; i++) {
    if (labels[i] == "" || length(labels[i]) > 63 || labels[i] !~ /^[A-Za-z0-9-]+$/ || labels[i] ~ /^-/ || labels[i] ~ /-$/) return 0
  }
  return 1
}

function emit(ip, domain, key) {
  domain = tolower(domain)
  sub(/\.$/, "", domain)
  if (!valid_domain(domain) || domain ~ /(^|\.)localhost$/ || domain == "ip6-allnodes" || domain == "ip6-localhost") return
  if (ip == "127.0.0.1" || ip == "127.0.0.0" || ip == "0.0.0.0" || ip == "::" || ip == "::1") ip = "0.0.0.0"
  key = domain SUBSEP ip
  if (!seen[key]++) print domain "\t" ip
}

{
  line = $0
  sub(/\r$/, "", line)
  if (NR == 1) {
    bom = sprintf("%c%c%c", 239, 187, 191)
    if (substr(line, 1, 3) == bom) line = substr(line, 4)
  }
  sub(/[[:space:]]*#.*/, "", line)
  gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
  if (line == "") next
  n = split(line, fields, /[[:space:]]+/)
  if (ipv4(fields[1]) || ipv6(fields[1])) {
    ip = fields[1]
    start = 2
  } else if (n == 1) {
    ip = "0.0.0.0"
    start = 1
  } else {
    next
  }
  for (i = start; i <= n; i++) emit(ip, fields[i])
}
