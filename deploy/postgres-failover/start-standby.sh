#!/bin/sh
set -eu

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  chmod 700 "$PGDATA"
  rm -rf "$PGDATA"/*
  until pg_isready -h primary -p 5432 -U postgres >/dev/null 2>&1; do
    sleep 1
  done
  pg_basebackup \
    --host=primary \
    --port=5432 \
    --username=authority_replicator \
    --pgdata="$PGDATA" \
    --format=plain \
    --wal-method=stream \
    --checkpoint=fast
  touch "$PGDATA/standby.signal"
  printf "%s\n" \
    "primary_conninfo = 'host=primary port=5432 user=authority_replicator password=replication-test-password application_name=authority_standby'" \
    >> "$PGDATA/postgresql.auto.conf"
fi

exec postgres -c hot_standby=on
