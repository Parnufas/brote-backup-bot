import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime"))
from core import (GitHub, guard, encrypt, decrypt, retention_keep,
                  fetch_bundle, sha, write_json, run)
from storage import verify_bytes
import storage
from database import connection_env
from bot import check_rehearsal
import bot


FIXTURE_CONFIG={'controller_repository':'tester/controller','vault_repository':'tester/vault','source_repository':'tester/application','project_ref':'abcdefghijklmnopqrst','rehearsal':{'ref':'a'*40,'path':'spec.json','sha256':'b'*64}}
SOURCE=FIXTURE_CONFIG['controller_repository']

class BackupTests(unittest.TestCase):
    def setUp(self):
        self.environment=patch.dict(os.environ,{'BACKUP_CONFIG':json.dumps(FIXTURE_CONFIG),'GITHUB_SHA':'c'*40,'BACKUP_APPROVED_SHA':'c'*40})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_encrypted_roundtrip_and_wrong_password(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source = root / 'data'
            source.mkdir()
            (source / 'database.dump').write_bytes(b'PRIVATE SQL SYNTHETIC\x00\xff')
            encrypted = encrypt(source, root, 'a-long-synthetic-password-' * 3)
            self.assertNotIn(b'PRIVATE SQL', encrypted.read_bytes())
            decrypt(encrypted,root/'restored',root,'a-long-synthetic-password-' * 3)
            self.assertEqual((source/'database.dump').read_bytes(),(root/'restored/database.dump').read_bytes())
            (root/'downloaded.tar.gz').unlink(missing_ok=True)
            with self.assertRaises(RuntimeError):
                decrypt(encrypted,root/'wrong',root,'wrong-password')

    def test_corrupted_ciphertext_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch); source=root/'data'; source.mkdir()
            (source/'dump').write_bytes(os.urandom(4096))
            encrypted=encrypt(source,root,'synthetic-secret-'*4)
            data=bytearray(encrypted.read_bytes()); data[len(data)//2]^=1; encrypted.write_bytes(data)
            with self.assertRaises(RuntimeError):
                decrypt(encrypted,root/'restored',root,'synthetic-secret-'*4)

    def test_inner_checksum_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch); plain=root/'input.tar.gz'
            with tarfile.open(plain,'w:gz') as archive:
                for name,content in [('dump',b'modified'),('checksums.json',b'{"dump":"wrong"}')]:
                    item=tarfile.TarInfo(name);item.size=len(content);archive.addfile(item,io.BytesIO(content))
            home=root/'gpg';home.mkdir(mode=0o700)
            encrypted=root/'input.gpg'
            run(['gpg','--homedir',str(home),'--batch','--pinentry-mode','loopback',
                 '--passphrase-fd','0','--symmetric','--s2k-count','65011712','--output',str(encrypted),str(plain)],data=b'synthetic-secret\n')
            with self.assertRaisesRegex(RuntimeError,'Inner checksum mismatch'):
                decrypt(encrypted,root/'restored',root,'synthetic-secret')

    def test_archive_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch);plain=root/'input.tar.gz'
            with tarfile.open(plain,'w:gz') as archive:
                item=tarfile.TarInfo('../escape');item.size=4;archive.addfile(item,io.BytesIO(b'data'))
            home=root/'gpg';home.mkdir(mode=0o700);encrypted=root/'input.gpg'
            run(['gpg','--homedir',str(home),'--batch','--pinentry-mode','loopback',
                 '--passphrase-fd','0','--symmetric','--s2k-count','65011712','--output',str(encrypted),str(plain)],data=b'synthetic-secret\n')
            with self.assertRaisesRegex(RuntimeError,'Unsafe archive member'):
                decrypt(encrypted,root/'restored',root,'synthetic-secret')
            self.assertFalse((root/'escape').exists())

    def test_branch_and_event_guards(self):
        source=Mock(); vault=Mock()
        source.call.side_effect=lambda path: {'protected':True} if path.endswith('/main') else {'private':False,'fork':False,'default_branch':'main','archived':False}
        vault.call.return_value={'private':True,'archived':False}
        good={'GITHUB_REPOSITORY':SOURCE,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch'}
        with patch.dict(os.environ,good):
            guard(source,vault)
            for key,value in [('GITHUB_REF','refs/heads/attacker'),('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REPOSITORY','fork/controller')]:
                with patch.dict(os.environ,{key:value}),self.assertRaises(RuntimeError):
                    guard(source,vault)
            source.call.side_effect=lambda path: {'protected':False} if path.endswith('/main') else {'private':False,'fork':False,'default_branch':'main','archived':False}
            with self.assertRaises(RuntimeError):guard(source,vault)
            source.call.side_effect=lambda path: {'protected':True} if path.endswith('/main') else {'private':False,'fork':False,'default_branch':'main','archived':False}
            vault.call.return_value={'private':False,'archived':False}
            with self.assertRaises(RuntimeError):guard(source,vault)

    def test_production_connection_allowlist(self):
        good={'PGHOST':'db.abcdefghijklmnopqrst.supabase.co','PGUSER':'postgres',
              'PGPASSWORD':'synthetic','PGDATABASE':'postgres','PGPORT':'5432'}
        with patch.dict(os.environ,good):
            self.assertEqual(connection_env()['PGSSLMODE'],'verify-full')
            for key,value in [('PGHOST','attacker.example'),('PGPORT','6543'),('PGDATABASE','other')]:
                with patch.dict(os.environ,{key:value}),self.assertRaises(RuntimeError):connection_env()

    def test_unapproved_commit_is_rejected_before_api_access(self):
        controller=Mock();vault=Mock()
        with patch.dict(os.environ,{'GITHUB_REPOSITORY':SOURCE,'GITHUB_REF':'refs/heads/main',
                                  'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_SHA':'d'*40}):
            with self.assertRaises(RuntimeError):guard(controller,vault)
        controller.call.assert_not_called()
        vault.call.assert_not_called()

    def test_controller_must_be_public_and_not_a_fork(self):
        controller=Mock();vault=Mock()
        for private,fork in [(True,False),(False,True)]:
            controller.call.return_value={'private':private,'fork':fork,'default_branch':'main','archived':False}
            with patch.dict(os.environ,{'GITHUB_REPOSITORY':SOURCE,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'schedule'}):
                with self.assertRaises(RuntimeError):guard(controller,vault)
        vault.call.assert_not_called()

    def test_asset_corruption_and_missing_parts(self):
        vault=Mock(); payload=b'encrypted-synthetic'
        manifest={'format':1,'parts':[{'name':'bundle.gpg.part000','bytes':len(payload),
                   'sha256':hashlib.sha256(payload).hexdigest()}], 'sha256':hashlib.sha256(payload).hexdigest()}
        vault.pages.return_value=[{'id':1,'name':'manifest.json'},{'id':2,'name':'bundle.gpg.part000'}]
        with tempfile.TemporaryDirectory() as root:
            vault.call.side_effect=[json.dumps(manifest).encode(),payload]
            self.assertEqual(fetch_bundle(vault,{'id':3},root)[0].read_bytes(),payload)
            vault.call.side_effect=[json.dumps(manifest).encode(),b'corrupt']
            with self.assertRaises(RuntimeError):fetch_bundle(vault,{'id':3},root)

    def test_retention_preserves_latest_pins_and_pre_migration(self):
        current=dt.datetime(2026,11,5,tzinfo=dt.timezone.utc)
        records=[{'id':i,'created_at':(current-dt.timedelta(days=i)).isoformat(),
                  'valid':True,'pinned':i==299,'pre_migration':i==25} for i in range(300)]
        records += [{'id':999,'created_at':current.isoformat(),'valid':False}]
        keep=retention_keep(records,current)
        self.assertTrue(set(range(14)).issubset(keep))
        self.assertTrue({0,25,299,999}.issubset(keep))
        self.assertNotIn(298,keep)
        self.assertLess(len(keep),35)

    def test_storage_requires_all_bytes_including_private_paths(self):
        with tempfile.TemporaryDirectory() as scratch:
            root=Path(scratch); (root/'objects').mkdir()
            obj={'bucket':'private','name':'../日本語/a photo.jpg','metadata':{'size':4},'version':'v1'}
            name='objects/'+hashlib.sha256(json.dumps([obj['bucket'],obj['name']],ensure_ascii=False).encode()).hexdigest()
            path=root/name; path.write_bytes(b'jpeg')
            write_json(root/'storage.json',{'buckets':[],'objects':[obj]})
            write_json(root/'storage-bytes.json',[dict(obj,file=name,bytes=4,sha256=sha(path))])
            self.assertEqual(verify_bytes(root),1)
            path.write_bytes(b'bad!')
            with self.assertRaises(RuntimeError):verify_bytes(root)

    def test_storage_captures_bytes_and_rejects_snapshot_race(self):
        obj={'bucket':'private','name':'folder/photo 日本語.jpg','metadata':{'size':4,'eTag':'etag'},'version':'v1'}
        env={'PGHOST':'synthetic','PGUSER':'synthetic','PGPASSWORD':'synthetic','PGDATABASE':'postgres','PGSSLROOTCERT':'synthetic'}
        for changed in (False,True):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as scratch:
                root=Path(scratch);write_json(root/'storage.json',{'buckets':[],'objects':[obj]})
                (root/'database.dump').write_bytes(b'dump')
                response=io.BytesIO(b'jpeg');response.headers={'ETag':'"etag"'}
                opener=Mock();opener.open.return_value=response
                conn=Mock();conn.__enter__=Mock(return_value=conn);conn.__exit__=Mock(return_value=False)
                conn.execute.return_value.fetchall.side_effect=[[] if changed else [('private',obj['name'],obj['metadata'],'v1')],[]]
                with patch.dict(os.environ,{'SUPABASE_SERVICE_ROLE_KEY':'synthetic'}), \
                        patch.object(storage.urllib.request,'build_opener',return_value=opener), \
                        patch.object(storage,'connection_env',return_value=env), \
                        patch.object(storage.psycopg,'connect',return_value=conn):
                    if changed:
                        with self.assertRaisesRegex(RuntimeError,'inventory changed'):storage.capture_bytes(root)
                    else:
                        self.assertEqual(storage.capture_bytes(root),(1,4))
                        self.assertEqual(verify_bytes(root),1)

    def test_changed_pr_cannot_reuse_migration_gate(self):
        source=Mock(); source.call.return_value={'head':{'sha':'changed'},'base':{'ref':'main'}}
        with self.assertRaises(RuntimeError):check_rehearsal(source,{'pr':1,'head_sha':'a'*40})

    def test_subprocess_errors_do_not_leak_details(self):
        with self.assertRaises(RuntimeError) as result:
            run(['python3','-c',"import sys; print('sensitive-row password',file=sys.stderr);sys.exit(1)"])
        self.assertNotIn('sensitive',str(result.exception))

    def test_no_production_secret_on_pr_workflow(self):
        root=Path(__file__).resolve().parents[1]
        pr=(root/'.github/workflows/tests.yml').read_text()
        production=(root/'.github/workflows/backup.yml').read_text()
        self.assertNotIn('secrets.',pr)
        self.assertNotIn('pull_request_target',production)
        self.assertNotIn('pull_request:',production)
        self.assertIn('environment: backup-production',production)
        self.assertIn("github.ref == 'refs/heads/main'",production)

    def test_failed_restore_never_publishes_valid_marker_or_prunes(self):
        source=Mock();vault=Mock();isolation=Mock()
        isolation.__enter__=Mock(return_value=isolation)
        isolation.__exit__=Mock(return_value=False)
        isolation.restore.side_effect=RuntimeError('Restored data differs from snapshot')
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{
                'BACKUP_MODE':'daily','GITHUB_SHA':'synthetic','GITHUB_RUN_ID':'1',
                'BACKUP_ENCRYPTION_PASSWORD':'synthetic-'*8,'GITHUB_STEP_SUMMARY':root+'/summary'}), \
                patch.object(bot,'clients',return_value=(source,vault)), \
                patch.object(bot,'run'),patch.object(bot,'capture',return_value='170006'), \
                patch.object(bot,'capture_bytes',return_value=(0,0)),patch.object(bot,'encrypt'), \
                patch.object(bot,'publish',return_value={'id':1}), \
                patch.object(bot,'fetch_bundle',return_value=(Path(root)/'cipher',{})), \
                patch.object(bot,'decrypt'),patch.object(bot,'verify_bytes',return_value=0), \
                patch.object(bot,'IsolatedPostgres',return_value=isolation), \
                patch.object(bot,'prune') as prune:
            with self.assertRaises(RuntimeError):bot.backup()
            vault.upload.assert_not_called()
            prune.assert_not_called()

    def test_monitor_marks_stale_backup_and_alerts(self):
        source=Mock(); vault=Mock()
        stale=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=31)).isoformat()
        record={'id':1,'valid':True,'tag_name':'synthetic','html_url':'https://github.com/private',
                'validation':{'backup_completed_at':stale,'restore_succeeded_at':stale,'backup_sha256':'hash'}}
        vault.pages.return_value=[]
        with tempfile.TemporaryDirectory() as root,patch.dict(os.environ,{
                'GITHUB_TOKEN':'synthetic','BACKUP_VAULT_TOKEN':'synthetic','GITHUB_RUN_ID':'1',
                'GITHUB_STEP_SUMMARY':root+'/summary'}), \
                patch.object(bot,'GitHub',side_effect=[source,vault]),patch.object(bot,'guard'), \
                patch.object(bot,'records',return_value=[record]),patch.object(bot,'set_issue') as issue:
            with self.assertRaises(RuntimeError):bot.monitor()
            self.assertNotIn(stale,Path(root+'/summary').read_text())
            self.assertIn('Health check failed',Path(root+'/summary').read_text())
            self.assertEqual(issue.call_args.kwargs['state'],'open')


if __name__=='__main__':unittest.main()
