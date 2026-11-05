"""Consistent PostgreSQL snapshot and a socket-only, disposable restore target."""
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

import psycopg
from psycopg import sql
from core import run, write_json
from settings import config

# Updated deliberately, never selected by workflow_dispatch or PR code.
IMAGE = "supabase/postgres:17.6.1.136@sha256:5a4314708484bec672de2c09653a5c01fb1c84a998564ac231b0325e2238ed5b"
DOCKER = ["docker", "--host=unix:///var/run/docker.sock"]

TABLES = """
select n.nspname, c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace
where c.relkind in ('r','m') and n.nspname not in ('pg_catalog','information_schema')
and n.nspname !~ '^pg_toast' and n.nspname !~ '^pg_temp'
and (not exists(select 1 from pg_depend d where d.classid='pg_class'::regclass
     and d.objid=c.oid and d.deptype='e')
     or c.oid in (select unnest(extconfig) from pg_extension))
order by n.nspname collate "C", c.relname collate "C"
"""

STRUCTURE = """
select json_build_object(
'columns', (select json_agg(x order by x.table_schema,x.table_name,x.ordinal_position) from
 (select table_schema,table_name,column_name,ordinal_position,data_type,udt_schema,udt_name,
 is_nullable,column_default,is_identity,is_generated,generation_expression
 from information_schema.columns where table_schema not in ('pg_catalog','information_schema')) x),
'constraints', (select json_agg(x order by x.schema,x.table_name,x.name) from
 (select n.nspname as schema,c.relname as table_name,k.conname as name,pg_get_constraintdef(k.oid) as definition
 from pg_constraint k join pg_class c on c.oid=k.conrelid join pg_namespace n on n.oid=c.relnamespace
 where n.nspname not in ('pg_catalog','information_schema')) x),
'indexes', (select json_agg(x order by x.schemaname,x.indexname) from
 (select schemaname,tablename,indexname,indexdef from pg_indexes where schemaname not in ('pg_catalog','information_schema')) x),
'policies', (select json_agg(x order by x.schemaname,x.tablename,x.policyname) from pg_policies x),
'rls', (select json_agg(x order by x.schema,x.name) from
 (select n.nspname as schema,c.relname as name,c.relrowsecurity,c.relforcerowsecurity
 from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in ('r','p')
 and n.nspname not in ('pg_catalog','information_schema') and n.nspname !~ '^pg_') x),
'functions', (select json_agg(x order by x.schema,x.name,x.args) from
 (select n.nspname as schema,p.proname as name,pg_get_function_identity_arguments(p.oid) as args,
 pg_get_functiondef(p.oid) as definition from pg_proc p join pg_namespace n on n.oid=p.pronamespace
 where n.nspname not in ('pg_catalog','information_schema') and p.prokind in ('f','p')
 and not exists(select 1 from pg_depend d where d.classid='pg_proc'::regclass and d.objid=p.oid and d.deptype='e')) x),
'triggers', (select json_agg(x order by x.schema,x.name,x.definition) from
 (select n.nspname as schema,c.relname as name,pg_get_triggerdef(t.oid) as definition
 from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace
 where not t.tgisinternal) x),
'views', (select json_agg(x order by x.schemaname,x.viewname) from
 (select schemaname,viewname,definition from pg_views where schemaname not in ('pg_catalog','information_schema')) x),
'extensions', (select json_agg(x order by x.extname) from
 (select e.extname,e.extversion,n.nspname from pg_extension e join pg_namespace n on n.oid=e.extnamespace) x),
'sequences', (select json_agg(x order by x.schemaname,x.sequencename) from
 (select schemaname,sequencename,data_type::text,start_value,min_value,max_value,increment_by,cycle,cache_size
 from pg_sequences) x)
)
"""


def ident(value):
    return '"' + value.replace('"', '""') + '"'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def normalize_structure(value):
    # Policy role arrays are name-sorted by PostgreSQL; normalize defensively.
    for policy in value.get('policies') or []:
        policy['roles'] = sorted(policy['roles'])
    return value


def row_query(schema, table):
    return f'SELECT to_jsonb(t)::text FROM ONLY {ident(schema)}.{ident(table)} t ORDER BY to_jsonb(t)::text COLLATE "C"'


def connection_env():
    env = os.environ.copy()
    for key in ('PGHOST', 'PGUSER', 'PGPASSWORD', 'PGDATABASE'):
        if not env.get(key):
            raise RuntimeError('Missing PostgreSQL secret: ' + key)
    project = config()['project_ref']
    if project not in env['PGHOST'] and project not in env['PGUSER']:
        raise RuntimeError('Connection must identify the configured project')
    if not env['PGHOST'].endswith('.supabase.com') and not env['PGHOST'].endswith('.supabase.co'):
        raise RuntimeError('Unexpected PostgreSQL host')
    if env.get('PGPORT', '5432') != '5432' or env['PGDATABASE'] != 'postgres':
        raise RuntimeError('Use direct connection or session pooler on port 5432')
    env.update(PGSSLMODE='verify-full', PGSSLROOTCERT='/etc/ssl/certs/ca-certificates.crt',
               PGCONNECT_TIMEOUT='30', PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=1800000 -c timezone=UTC')
    return env


def capture(destination):
    destination = Path(destination)
    env = connection_env()
    params = {k[2:].lower(): env[k] for k in ('PGHOST', 'PGUSER', 'PGPASSWORD', 'PGDATABASE')}
    params['dbname'] = params.pop('database')
    params.update(port=5432, sslmode='verify-full', sslrootcert=env['PGSSLROOTCERT'], connect_timeout=30)
    with psycopg.connect(**params) as conn:
        conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        conn.execute("SET LOCAL timezone='UTC'")
        conn.execute("SET LOCAL search_path=pg_catalog")
        conn.execute("SET LOCAL statement_timeout='30min'")
        version = conn.execute('SHOW server_version_num').fetchone()[0]
        if int(version) // 10000 != 17:
            raise RuntimeError('Server major differs from reviewed PostgreSQL 17 image')
        if conn.execute("select count(*) from pg_foreign_table").fetchone()[0]:
            raise RuntimeError('Foreign tables require an explicit external-data backup strategy')
        snapshot = conn.execute('select pg_export_snapshot()').fetchone()[0]
        roles = conn.execute("select rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls from pg_roles where rolname !~ '^pg_' order by rolname").fetchall()
        write_json(destination / 'roles.json', roles)  # Deliberately no password hashes.
        tables = conn.execute(TABLES).fetchall()
        fingerprints = {}
        for schema, table in tables:
            h = hashlib.sha256()
            count = 0
            with conn.cursor(name='brote_' + uuid.uuid4().hex) as cursor:
                cursor.execute(row_query(schema, table))
                for (row,) in cursor:
                    h.update((row + '\n').encode())
                    count += 1
            fingerprints[f'{schema}.{table}'] = {'rows': count, 'sha256': h.hexdigest()}
        structure = normalize_structure(conn.execute(STRUCTURE).fetchone()[0])
        # The same exported snapshot backs both the dump and all verification evidence.
        args = DOCKER + ['run', '--rm', '--entrypoint', 'pg_dump']
        for name in ('PGHOST','PGUSER','PGPASSWORD','PGDATABASE','PGSSLMODE','PGCONNECT_TIMEOUT','PGOPTIONS'):
            args += ['-e', name]
        args += ['-e', 'PGSSLROOTCERT=/run/ca.pem', '--mount',
                 'type=bind,src=/etc/ssl/certs/ca-certificates.crt,dst=/run/ca.pem,readonly',
                 IMAGE, '--format=custom', '--snapshot=' + snapshot, '--no-publications', '--no-subscriptions']
        with open(destination / 'database.dump', 'wb') as output:
            run(args, env=env, output=output)
        write_json(destination / 'database.json', {'server_version_num': version,
                    'tables': tables, 'fingerprints': fingerprints, 'structure': structure})
        # Inventory from exactly the database snapshot that was dumped.
        objects = conn.execute('select bucket_id,name,metadata,version from storage.objects order by bucket_id,name').fetchall()
        buckets = conn.execute('select to_jsonb(b) from storage.buckets b order by id').fetchall()
        write_json(destination / 'storage.json', {'buckets': [b[0] for b in buckets],
                  'objects': [{'bucket': b,'name': n,'metadata': m,'version': v} for b,n,m,v in objects]})
        return version


class IsolatedPostgres:
    def __init__(self):
        self.name = 'brote-restore-' + uuid.uuid4().hex

    def __enter__(self):
        # No ports, no network, no production credentials; bypass all Supabase init scripts.
        preload = 'pg_cron' if IMAGE.startswith('supabase/') else ''
        command = ('mkdir /tmp/brote-pg; chown postgres:postgres /tmp/brote-pg; '
                   'if command -v su-exec >/dev/null; then demote=(su-exec postgres); '
                   'else demote=(runuser -u postgres --); fi; '
                   '"${demote[@]}" initdb -D /tmp/brote-pg -U postgres --auth=trust >/dev/null; '
                   'exec "${demote[@]}" postgres -D /tmp/brote-pg '
                   "-c listen_addresses='' -c unix_socket_directories=/tmp "
                   f"-c shared_preload_libraries='{preload}' -c cron.database_name=postgres -c cron.launch_active_jobs=off")
        run(DOCKER + ['run','-d','--name',self.name,'--network=none','--user=0',
                     '--cap-drop=ALL','--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN',
                     '--security-opt=no-new-privileges','--memory=3g','--cpus=2',
                     '--tmpfs','/tmp:rw,nosuid,size=5g','--entrypoint','bash',IMAGE,'-euc',command])
        for _ in range(60):
            try:
                self.query('select 1')
                return self
            except RuntimeError:
                time.sleep(1)
        self.__exit__(None, None, None)
        raise RuntimeError('Isolated PostgreSQL did not become ready')

    def __exit__(self, *args):
        run(DOCKER + ['rm','-f',self.name])

    def query(self, query):
        return run(DOCKER + ['exec','-i',self.name,'psql','-X','-h','/tmp','-U','postgres',
                            '-d','postgres','-v','ON_ERROR_STOP=1','-Atq'],
                   data=("SET timezone='UTC';\n" + query + ';\n').encode()).decode().strip()

    def restore(self, directory):
        directory = Path(directory)
        roles = json.loads((directory / 'roles.json').read_text())
        for role in roles:
            if role[0] != 'postgres':
                self.query('CREATE ROLE ' + ident(role[0]) + ' NOLOGIN')
        # Payload preserves original ACL/ownership; drill intentionally uses postgres ownership.
        with (directory / 'database.dump').open('rb') as dump:
            run(DOCKER + ['exec','-i',self.name,'pg_restore','-h','/tmp','-U','postgres','-d','postgres',
                         '--exit-on-error','--no-owner','--no-publications','--no-subscriptions'], input_file=dump)
        return self.verify(directory)

    def verify(self, directory):
        directory = Path(directory)
        expected = json.loads((directory / 'database.json').read_text())
        actual_structure = normalize_structure(json.loads(self.query('SET search_path=pg_catalog;\n' + STRUCTURE)))
        if canonical(actual_structure) != canonical(expected['structure']):
            raise RuntimeError('Restored structure differs from snapshot')
        for schema, table in expected['tables']:
            # Stream COPY output to disk, never to Actions logs or process memory.
            output = directory / 'rows.check'
            query = "COPY (" + row_query(schema, table) + ") TO STDOUT"
            with output.open('wb') as f:
                run(DOCKER + ['exec','-i',self.name,'psql','-X','-h','/tmp','-U','postgres',
                             '-v','ON_ERROR_STOP=1','-Atq'],
                    data=("SET timezone='UTC';\n" + query + ';\n').encode(), output=f)
            # COPY text escapes backslashes and control characters; decode before hashing.
            h = hashlib.sha256()
            count = 0
            with output.open('rb') as f:
                for row in f:
                    row = row.rstrip(b'\n').replace(b'\\\\', b'\\')
                    h.update(row + b'\n')
                    count += 1
            output.unlink()
            if expected['fingerprints'][f'{schema}.{table}'] != {'rows':count,'sha256':h.hexdigest()}:
                raise RuntimeError('Restored data differs from snapshot')
        return len(expected['tables'])
