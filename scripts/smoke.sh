#!/usr/bin/env bash
# Быстрая проверка развёрнутой админки (без обращения к Remnawave).
# Использование: BASE=http://127.0.0.1:8090 ADMIN_USER=admin ADMIN_PASS=... bash scripts/smoke.sh
set -u
BASE="${BASE:-http://127.0.0.1:8090}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"

fail=0
check() { # name, http_code, expected
  local name="$1" code="$2" want="$3"
  if [[ "$code" == "$want" ]]; then
    echo "ok    $name -> $code"
  else
    echo "FAIL  $name -> $code (ожидалось $want)"
    fail=1
  fi
}

code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/healthz")
check "healthz" "$code" 200

code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/login")
check "login page" "$code" 200

code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/")
check "root tanpa session (redirect)" "$code" 200
[[ "$code" == "307" || "$code" == "302" ]] || { echo "note: root должен редиректить на /login"; }

if [[ -n "$ADMIN_PASS" ]]; then
  jar=$(mktemp)
  code=$(curl -sk -o /dev/null -w '%{http_code}' -c "$jar" -b "$jar" \
    -X POST "$BASE/login" \
    -d "username=$ADMIN_USER" -d "password=$ADMIN_PASS" \
    -H 'Content-Type: application/x-www-form-urlencoded')
  # после логина происходит редирект на /
  code2=$(curl -sk -o /dev/null -w '%{http_code}' -L -b "$jar" "$BASE/")
  check "login + dashboard" "$code2" 200
  code3=$(curl -sk -o /dev/null -w '%{http_code}' -b "$jar" "$BASE/access")
  check "admin page /access" "$code3" 200
  rm -f "$jar"
else
  echo "note: ADMIN_PASS не задан — пропуск проверки логина"
fi

code=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/botx/status")
check "botx status (no params -> 200/4xx от pybotx)" "$code" "200"

exit $fail
