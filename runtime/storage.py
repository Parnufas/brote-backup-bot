"""Back up real Storage bytes, indexed by hashed paths, without logging names."""
import hashlib
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

import psycopg
from core import MAX_BYTES, sha, write_json
from settings import config
from database import connection_env


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('Storage redirects are forbidden')


def capture_bytes(directory, ca_path):
    directory = Path(directory)
    inventory = json.loads((directory / 'storage.json').read_text())
    key = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')
    if not key:
        raise RuntimeError('Missing Storage service credential')
    objects = directory / 'objects'
    objects.mkdir(mode=0o700)
    index = []
    total = (directory / 'database.dump').stat().st_size
    opener = urllib.request.build_opener(NoRedirect())
    for item in inventory['objects']:
        identity = json.dumps([item['bucket'],item['name']], ensure_ascii=False).encode()
        name = hashlib.sha256(identity).hexdigest()
        path = objects / name
        encoded = '/'.join(urllib.parse.quote(s, safe='') for s in [item['bucket'],item['name']])
        url = f"https://{config()['project_ref']}.supabase.co/storage/v1/object/authenticated/{encoded}"
        request = urllib.request.Request(url, headers={'Authorization':'Bearer ' + key, 'apikey':key})
        with opener.open(request, timeout=120) as response, path.open('wb') as output:
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > MAX_BYTES:
                    raise RuntimeError('Data exceeds the reviewed 4 GiB vault budget')
                output.write(block)
            etag = response.headers.get('ETag', '').strip('"')
        metadata = item['metadata'] or {}
        expected_size = metadata.get('size')
        expected_etag = metadata.get('eTag')
        if expected_size is None or path.stat().st_size != int(expected_size):
            raise RuntimeError('Storage byte size differs from database snapshot')
        if expected_etag and str(expected_etag).strip('"') != etag:
            raise RuntimeError('Storage object changed since database snapshot')
        index.append(dict(item, file='objects/' + name, sha256=sha(path), bytes=path.stat().st_size))
    # Detect additions, overwrites, and removals while bytes were being fetched.
    env = connection_env(ca_path)
    with psycopg.connect(host=env['PGHOST'],user=env['PGUSER'],password=env['PGPASSWORD'],
                         dbname=env['PGDATABASE'],port=5432,sslmode='verify-full',
                         sslrootcert=env['PGSSLROOTCERT'],connect_timeout=30,
                         options='-c default_transaction_read_only=on -c statement_timeout=60000') as conn:
        rows = conn.execute('select bucket_id,name,metadata,version from storage.objects order by bucket_id,name').fetchall()
        after = [{'bucket':b,'name':n,'metadata':m,'version':v} for b,n,m,v in rows]
        buckets = [b[0] for b in conn.execute('select to_jsonb(b) from storage.buckets b order by id').fetchall()]
    if after != inventory['objects'] or buckets != inventory['buckets']:
        raise RuntimeError('Storage inventory changed during backup; retry in a quiet window')
    write_json(directory / 'storage-bytes.json', index)
    return len(index), sum(i['bytes'] for i in index)


def verify_bytes(directory):
    directory = Path(directory)
    inventory = json.loads((directory / 'storage.json').read_text())
    index = json.loads((directory / 'storage-bytes.json').read_text())
    if [{k:i[k] for k in ('bucket','name','metadata','version')} for i in index] != inventory['objects']:
        raise RuntimeError('Storage inventory and byte index differ')
    expected = set()
    for item in index:
        identity = json.dumps([item['bucket'],item['name']], ensure_ascii=False).encode()
        name = 'objects/' + hashlib.sha256(identity).hexdigest()
        if item['file'] != name or name in expected:
            raise RuntimeError('Unsafe or duplicate Storage path')
        expected.add(name)
        path = directory / name
        if path.stat().st_size != item['bytes'] or sha(path) != item['sha256']:
            raise RuntimeError('Storage content checksum mismatch')
    actual = {str(p.relative_to(directory)) for p in (directory / 'objects').iterdir()}
    if actual != expected:
        raise RuntimeError('Unexpected or missing Storage bytes')
    return len(index)
