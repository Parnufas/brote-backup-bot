"""Supabase-shaped synthetic fixture; no connection to production or real backup."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import database
from database import IsolatedPostgres,TABLES,STRUCTURE,DOCKER,row_query
from core import run,write_json,SafeFailure

ROLES=['anon','authenticated','service_role','authenticator','supabase_admin','supabase_auth_admin',
       'supabase_storage_admin','supabase_replication_admin','supabase_functions_admin',
       'supabase_read_only_user','dashboard_user','pgbouncer','pgsodium_keyholder',
       'pgsodium_keyiduser','pgsodium_keymaker']
SCHEMAS=['public','auth','storage','extensions','vault','realtime','graphql_public','pgbouncer','supabase_migrations']


def fixture(source):
    existing=json.loads(source.query("select json_agg(rolname) from pg_roles where rolname !~ '^pg_'"))
    for role in ROLES:
        if role not in existing:source.query('create role '+database.ident(role)+' nologin')
    for schema in SCHEMAS:source.query('create schema if not exists '+database.ident(schema))
    if database.IMAGE.startswith('supabase/'):
        for extension in ('pg_stat_statements','pgcrypto','uuid-ossp'):
            source.query('create extension '+database.ident(extension)+' with schema extensions')
        source.query('create extension supabase_vault')
    source.query("""
create function auth.uid() returns uuid language sql stable as $$select null::uuid$$;
create type public.fixture_state as enum ('new','saved');
create table public.fixture_events(id int generated always as identity primary key,body jsonb,payload bytea,state public.fixture_state);
insert into public.fixture_events(body,payload,state) values ('{"text":"Niño 日本語 \\n \\\\"}',decode('00ffabcd','hex'),'saved');
create table auth.fixture_users(id uuid primary key);
alter table auth.fixture_users add column legacy_a text,add column retained text,add column legacy_b text,add column note jsonb;
alter table auth.fixture_users drop column legacy_a,drop column legacy_b;
alter table auth.fixture_users add column retained_length int generated always as(length(retained)) stored;
insert into auth.fixture_users(id,retained,note) values('00000000-0000-0000-0000-000000000001','synthetic','{"fixture":true}');
create table storage.fixture_objects(id int primary key,user_id uuid references auth.fixture_users(id),metadata jsonb);
create table realtime.fixture_refs(id int primary key,entity regclass,datatype regtype);
create table storage.fixture_events(id int primary key);
insert into realtime.fixture_refs values(1,'public.fixture_events'::regclass,'public.fixture_state'::regtype);
insert into realtime.fixture_refs values(2,'storage.fixture_events'::regclass,'public.fixture_state'::regtype);
alter table public.fixture_events enable row level security;
create policy fixture_owner on public.fixture_events to authenticated using (true);
grant select on public.fixture_events to authenticated;
create view graphql_public.fixture_view with(security_invoker=true) as select id,state from public.fixture_events;
create function pgbouncer.fixture_auth() returns text language sql security definer set search_path='' as $$select 'synthetic'::text$$;
alter function pgbouncer.fixture_auth() owner to supabase_admin;
alter table public.fixture_events owner to supabase_admin;
alter table auth.fixture_users owner to supabase_auth_admin;
alter table storage.fixture_objects owner to supabase_storage_admin;
alter table realtime.fixture_refs owner to authenticator;
create function extensions.fixture_ddl() returns event_trigger language plpgsql as $$begin return; end$$;
""")
    for i in range(6):source.query(f'create event trigger fixture_ddl_{i} on ddl_command_end execute function extensions.fixture_ddl()')


def capture_fixture(source,data):
    tables=json.loads(source.query('select json_agg(t) from ('+TABLES+') t'))
    tables=[[t['nspname'],t['relname']] for t in tables]
    fingerprints={}
    for schema,table in tables:
        rows=json.loads(source.query("SET search_path=pg_catalog; select coalesce(json_agg(row),'[]'::json) from ("+row_query(schema,table)+') as r(row)'))
        fingerprints[f'{schema}.{table}']={'rows':len(rows),'sha256':hashlib.sha256(''.join(r+'\n' for r in rows).encode()).hexdigest()}
    write_json(data/'database.json',{'tables':tables,'fingerprints':fingerprints,
               'structure':json.loads(source.query('SET search_path=pg_catalog;'+STRUCTURE))})
    roles=json.loads(source.query("select json_agg(t) from (select rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls from pg_roles where rolname !~ '^pg_' order by rolname) t"))
    write_json(data/'roles.json',[list(r.values()) for r in roles])
    with (data/'database.dump').open('wb') as output:
        run(DOCKER+['exec',source.name,'pg_dump','-h','/tmp','-U','postgres','--format=custom','--no-publications','--no-subscriptions'],output=output)
    return len(tables)


def main():
    if os.environ.get('BACKUP_TEST_IMAGE'):database.IMAGE=os.environ['BACKUP_TEST_IMAGE']
    run(DOCKER+['pull',database.IMAGE])
    with tempfile.TemporaryDirectory(prefix='brote-restore-fixture-') as scratch:
        data=Path(scratch)
        with IsolatedPostgres() as source:
            fixture(source)
            count=capture_fixture(source,data)
        with IsolatedPostgres() as target:
            target.restore(data)
            assert target.query("select nextval('public.fixture_events_id_seq')")=='2'
            assert target.query("select count(*) from pg_roles where rolname !~ '^pg_' and rolname<>'postgres' and rolcanlogin")=='0'
            target.query("update realtime.fixture_refs set entity='storage.fixture_events'::regclass where id=1")
            try:target.verify(data)
            except SafeFailure as error:assert error.category=='RESTORE_DATA_MISMATCH'
            else:raise AssertionError('Changed object reference accepted')
            target.query("update realtime.fixture_refs set entity='public.fixture_events'::regclass where id=1")
            target.verify(data)
            target.query('alter table auth.fixture_users alter column retained set not null')
            try:target.verify(data)
            except SafeFailure as error:assert error.category=='RESTORE_STRUCTURE_MISMATCH'
            else:raise AssertionError('Changed nullability accepted')
            target.query('alter table auth.fixture_users alter column retained drop not null')
            target.verify(data)
            target.query('alter table public.fixture_events add column unexpected int')
            try:target.verify(data)
            except SafeFailure as error:assert error.category=='RESTORE_STRUCTURE_MISMATCH'
            else:raise AssertionError('Changed structure accepted')
        print(f'PASS: Supabase-shaped synthetic restore with 16 roles, 9 schemas, 5 owners, 6 event triggers and {count} tables.')


if __name__=='__main__':main()
