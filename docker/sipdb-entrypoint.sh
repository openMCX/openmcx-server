#!/bin/bash
# Starts the pre-initialised MySQL of Dockerfile.sipdb and applies what the official
# image's entrypoint would: the root and MYSQL_USER passwords from their files, the
# MYSQL_DATABASE, and the scripts in /docker-entrypoint-initdb.d. The server runs once;
# the SIP core waits for the health check, which needs the lab's subscriber table.
set -euo pipefail
datadir=/var/lib/mysql-baked
root_pw=$(cat "$MYSQL_ROOT_PASSWORD_FILE")
user_pw=$(cat "$MYSQL_PASSWORD_FILE")
for value in "$root_pw" "$user_pw" "$MYSQL_USER" "$MYSQL_DATABASE"; do
  # Lab secrets and names are generated hex and words; anything else is refused
  # rather than quoted into SQL.
  [[ "$value" =~ ^[A-Za-z0-9_]+$ ]] || { echo "sipdb: unexpected characters in a setting" >&2; exit 1; }
done
socket=/var/run/mysqld/mysqld.sock
mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld
mysqld --user=mysql --datadir="$datadir" --socket="$socket" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null; wait "$pid"' TERM INT
for _ in $(seq 1 300); do
  mysqladmin --socket="$socket" -uroot ping >/dev/null 2>&1 && break
  kill -0 "$pid" 2>/dev/null || exit 1
  sleep 0.1
done
mysql --socket="$socket" -uroot <<SQL
CREATE DATABASE IF NOT EXISTS \`$MYSQL_DATABASE\`;
CREATE USER '$MYSQL_USER'@'%' IDENTIFIED BY '$user_pw';
GRANT ALL ON \`$MYSQL_DATABASE\`.* TO '$MYSQL_USER'@'%';
CREATE USER 'root'@'%' IDENTIFIED BY '$root_pw';
GRANT ALL ON *.* TO 'root'@'%' WITH GRANT OPTION;
ALTER USER 'root'@'localhost' IDENTIFIED BY '$root_pw';
SQL
for script in /docker-entrypoint-initdb.d/*.sql; do
  [ -e "$script" ] || continue
  MYSQL_PWD="$root_pw" mysql --socket="$socket" -uroot "$MYSQL_DATABASE" < "$script"
done
echo "sipdb: ready"
wait "$pid"
