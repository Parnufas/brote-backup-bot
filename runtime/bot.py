#!/usr/bin/env python3
"""Brote Backup Bot: secrets only on protected main, restore only in Docker."""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from core import (GitHub,
                  guard, now, write_json, encrypt, decrypt, publish, fetch_bundle,
                  retention_keep)
from database import IMAGE, DOCKER, capture, IsolatedPostgres, postgres_ca
from storage import capture_bytes, verify_bytes
from core import run, set_stage, failure_code, SafeFailure
from settings import config, controller_repo, vault_repo, source_repo, mask_private_config


def clients():
    controller = GitHub(os.environ.get('GITHUB_TOKEN'))
    vault = GitHub(os.environ.get('BACKUP_VAULT_TOKEN'))
    guard(controller, vault)
    return controller, vault


def load_rehearsal(source):
    pointer = config()['rehearsal']
    content = source.call(f"repos/{source_repo()}/contents/{pointer['path']}?ref={pointer['ref']}")
    raw = base64.b64decode(content['content'])
    if hashlib.sha256(raw).hexdigest() != pointer['sha256']:
        raise RuntimeError('Private rehearsal specification hash mismatch')
    return json.loads(raw)


def check_rehearsal(source, spec):
    pr = source.call(f"repos/{source_repo()}/pulls/{int(spec['pr'])}")
    if pr['head']['sha'] != spec['head_sha'] or pr['base']['ref'] != 'main':
        raise RuntimeError('The candidate changed; review the private rehearsal specification')


def rehearse(source, database, work, spec):
    check_rehearsal(source, spec)
    content = source.call(f"repos/{source_repo()}/contents/{spec['path']}?ref={spec['head_sha']}")
    migration = base64.b64decode(content['content'])
    if hashlib.sha256(migration).hexdigest() != spec['sha256']:
        raise RuntimeError('Migration hash mismatch')
    # SQL and checks run only inside the networkless container; never on the host.
    database.query(migration.decode())
    database.query(migration.decode())
    result = json.loads(database.query(spec['checks_sql']))
    if result != spec['expected']:
        raise RuntimeError('Migration checks failed')
    from database import row_query
    expected = json.loads((Path(work) / 'restored/database.json').read_text())
    for schema, table in expected['tables']:
        fingerprint = table_fingerprint(database, schema, table)
        if fingerprint != database.before_rehearsal[f'{schema}.{table}']:
            raise RuntimeError('Migration changed existing records')
    check_rehearsal(source, spec)
    return {'pr':spec['pr'],'head_sha':spec['head_sha'],'migration_sha256':spec['sha256'],
            'checks':result,'remote_execution_authorized':False}


def table_fingerprint(database, schema, table):
    from database import row_query
    query = "select json_build_object('rows',count(*),'md5',md5(coalesce(string_agg(row, E'\\n' order by row collate \"C\"),''))) from (" + row_query(schema,table) + ") as r(row)"
    return database.query(query)


def before_rehearsal(database, directory):
    expected = json.loads((directory / 'database.json').read_text())
    database.before_rehearsal = {f'{schema}.{table}': table_fingerprint(database,schema,table)
                               for schema,table in expected['tables']}


def public_summary(message):
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as output:
        output.write(message + '\n')


def backup():
    set_stage('CONTROL')
    print('Brote Backup Bot: checking protected main and private vault',flush=True)
    controller, vault = clients()
    mode = os.environ.get('BACKUP_MODE', 'daily')
    if mode not in {'daily','pre-migration','restore-latest'}:
        raise RuntimeError('Invalid backup operation')
    if mode == 'pre-migration':
        source = GitHub(os.environ.get('BACKUP_SOURCE_READ_TOKEN'))
        spec = load_rehearsal(source)
        check_rehearsal(source, spec)
    password = os.environ.get('BACKUP_ENCRYPTION_PASSWORD', '')
    run(DOCKER + ['pull',IMAGE])
    with tempfile.TemporaryDirectory(prefix='brote-', dir=os.environ.get('RUNNER_TEMP')) as scratch:
        work = Path(scratch)
        if mode == 'restore-latest':
            release = latest_valid(vault)[0]
        else:
            data = work / 'data'
            data.mkdir(mode=0o700)
            started = now()
            print('Brote Backup Bot: capturing consistent PostgreSQL snapshot',flush=True)
            with postgres_ca() as ca_path:
                version = capture(data, ca_path)
                print('Brote Backup Bot: capturing and reconciling Storage bytes',flush=True)
                set_stage('STORAGE_BYTES')
                object_count, storage_bytes = capture_bytes(data, ca_path)
            print('Brote Backup Bot: encrypting and publishing private backup',flush=True)
            set_stage('ENCRYPT')
            encrypted = encrypt(data, work, password)
            metadata = {'backup_started_at':started,'backup_completed_at':now(),
                        'source_commit':os.environ['GITHUB_SHA'],'project':config()['project_ref'],
                        'postgres_image':IMAGE,'server_version_num':version,
                        'storage_objects':object_count,'storage_bytes':storage_bytes,
                        'pre_migration':mode == 'pre-migration',
                        'run_url':f"https://github.com/{controller_repo()}/actions/runs/{os.environ['GITHUB_RUN_ID']}"}
            set_stage('PUBLISH')
            release = publish(vault, encrypted, work, metadata)
        print('Brote Backup Bot: downloading and verifying stored ciphertext',flush=True)
        set_stage('DOWNLOAD')
        encrypted, manifest = fetch_bundle(vault, release, work)
        set_stage('DECRYPT')
        decrypt(encrypted, work / 'restored', work, password)
        object_count = verify_bytes(work / 'restored')
        set_stage('RESTORE')
        with IsolatedPostgres() as database:
            print('Brote Backup Bot: restoring and comparing structure and data in isolation',flush=True)
            tables = database.restore(work / 'restored')
            rehearsal = None
            if mode == 'pre-migration':
                print('Brote Backup Bot: rehearsing approved migration in isolation',flush=True)
                before_rehearsal(database, work / 'restored')
                set_stage('REHEARSAL')
                rehearsal = rehearse(source, database, work, spec)
        validation = {'valid':True,'backup_sha256':manifest['sha256'],
                      'backup_completed_at':manifest['backup_completed_at'],
                      'restore_succeeded_at':now(),'tables_verified':tables,
                      'storage_objects_verified':object_count,
                      'pre_migration':manifest['pre_migration'],'rehearsal':rehearsal,
                      'run_url':f"https://github.com/{controller_repo()}/actions/runs/{os.environ['GITHUB_RUN_ID']}"}
        if mode == 'restore-latest':
            # Immutable historical validation stays intact; append a new dated drill record.
            path = work / ('restore-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'] + '.json')
        else:
            path = work / 'validation.json'
        write_json(path, validation)
        print('Brote Backup Bot: persisting successful validation',flush=True)
        set_stage('VALIDATION')
        vault.upload(release, path)
        # Only prune after a full successful round-trip. Refuse public vault again before deletes.
        guard(controller, vault)
        set_stage('RETENTION')
        prune(vault)
        public_summary('Backup and isolated restore completed. Detailed status is private.')



def records(vault):
    releases = vault.pages(f'repos/{vault_repo()}/releases')
    result = []
    for release in releases:
        if not re.fullmatch(r'brote-\d{8}T\d{6}Z-\d+-\d+', release['tag_name']):
            continue
        assets = vault.pages(f"repos/{vault_repo()}/releases/{release['id']}/assets")
        by_name = {a['name']:a for a in assets}
        validation = None
        if 'validation.json' in by_name:
            validation = json.loads(vault.call(f"repos/{vault_repo()}/releases/assets/{by_name['validation.json']['id']}",binary=True))
        # Explicit retention pin: rename release to start [KEEP].
        result.append(dict(release, valid=bool(validation and validation.get('valid')),
                           validation=validation, pinned=release['name'].startswith('[KEEP]'),
                           pre_migration=bool(validation and validation.get('pre_migration'))))
    return sorted(result,key=lambda r:r['created_at'],reverse=True)


def latest_valid(vault):
    values = [r for r in records(vault) if r['valid']]
    if not values:
        raise RuntimeError('No validated backup exists')
    return values[0], values[0]['validation']


def prune(vault):
    values = records(vault)
    keep = retention_keep(values, dt.datetime.now(dt.timezone.utc))
    for release in values:
        if release['id'] not in keep:
            vault.call(f"repos/{vault_repo()}/releases/{release['id']}",'DELETE')
            # Delete only the matching bot-owned tag, never branch contents.
            vault.call(f"repos/{vault_repo()}/git/refs/tags/{release['tag_name']}",'DELETE')


def set_issue(vault, title, body, *, state='open'):
    login = vault.call('user')['login']
    issues = vault.pages(f'repos/{vault_repo()}/issues?state=all&creator=' + login)
    issue = next((i for i in issues if i['title'] == title and 'pull_request' not in i), None)
    if issue:
        vault.call(f"repos/{vault_repo()}/issues/{issue['number']}",'PATCH',{'body':body,'state':state})
    elif state == 'open':
        vault.call(f'repos/{vault_repo()}/issues','POST',{'title':title,'body':body})


def monitor():
    controller = GitHub(os.environ.get('GITHUB_TOKEN'))
    vault = GitHub(os.environ.get('BACKUP_VAULT_TOKEN'))
    set_stage('HEALTH_CONTROL')
    failure = os.environ.get('BACKUP_JOB_RESULT','success') != 'success'
    health_error = None
    try:
        guard(controller, vault)
        set_stage('HEALTH_READ')
        values = records(vault)
        valid = next(((r,r['validation']) for r in values if r['valid']),None)
        if valid is None:raise SafeFailure('NO_VALID_BACKUP')
        release, validation = valid
        last_backup = dt.datetime.fromisoformat(validation['backup_completed_at'])
        last_restore = dt.datetime.fromisoformat(validation['restore_succeeded_at'])
        # Newer repeat-restore records may advance the last successful restore date.
        assets = vault.pages(f"repos/{vault_repo()}/releases/{release['id']}/assets")
        for asset in assets:
            if asset['name'].startswith('restore-') and asset['name'].endswith('.json'):
                drill = json.loads(vault.call(f"repos/{vault_repo()}/releases/assets/{asset['id']}",binary=True))
                if drill.get('valid') and drill['backup_sha256'] == validation['backup_sha256']:
                    last_restore = max(last_restore,dt.datetime.fromisoformat(drill['restore_succeeded_at']))
        current = dt.datetime.now(dt.timezone.utc)
        failure |= current - last_backup > dt.timedelta(hours=30)
        failure |= current - last_restore > dt.timedelta(hours=30)
        failure |= bool(values and not values[0]['valid'])
        body = (f"**{'REQUIERE ATENCIÓN' if failure else 'BACKUP VÁLIDO'}**\n\n"
                f"Último respaldo validado: {last_backup.isoformat()}\n\n"
                f"Última restauración satisfactoria: {last_restore.isoformat()}\n\n"
                f"Respaldo: `{release['tag_name']}` · [almacén privado]({release['html_url']})\n\n"
                f"Comprobado: {now()}. Caduca a las 30 h sin nuevo backup/restauración.\n\n"
                'Cada ejecución diaria restaura la copia descargada y verifica estructura, datos y bytes de Storage.\n')
    except Exception as error:
        health_error = error
        print('::error::' + failure_code(error),flush=True)
        failure = True
        body = f'**SIN BACKUP VÁLIDO COMPROBABLE**\n\nComprobado: {now()}. Revisar configuración y ejecución; no autorizar migraciones destructivas.'
    run_url = f"https://github.com/{controller_repo()}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    body += f'\n[Última comprobación]({run_url})\n'
    set_stage('HEALTH_NOTIFY')
    set_issue(vault,'Brote Backup Bot · estado',body)
    set_issue(vault,'Brote Backup Bot · fallo de backup o restauración',body,
              state='open' if failure else 'closed')
    public_summary('Health check failed. See the private vault.' if failure else 'Health check passed. Detailed status is private.')
    if failure:
        set_stage('HEALTH_RESULT')
        if health_error is not None and isinstance(health_error,SafeFailure):raise health_error
        raise SafeFailure('HEALTH_UNAVAILABLE' if health_error else 'BACKUP_UNHEALTHY')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        mask_private_config()
        {'backup':backup,'monitor':monitor}[sys.argv[1]]()
    except Exception as error:
        print('::error::' + failure_code(error),flush=True)
        # Never emit exception text / traceback: responses can contain PII or credentials.
        # Our exact RuntimeError instances contain only fixed, sanitized diagnostics.
        # Public logs must not include even fragments of private exception data.
        print('::error::Brote Backup Bot failed. Inspect the failed step and the recovery runbook; no sensitive output retained.')
        sys.exit(1)
