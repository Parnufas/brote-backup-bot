"""Real libpq TLS checks against a disposable synthetic database, never production."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import psycopg
import database
from core import run, set_stage, SafeFailure, pg_category

IMAGE='postgres:17.6-bookworm@sha256:f3bd19c606e442c3d7bdfa8002e03fe260a1023351e0ea4598032022b68dd6e3'
D=database.DOCKER


def certificates(root):
    for name in ('ca','untrusted'):
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
             '-subj','/CN=Synthetic TLS Test CA','-addext','basicConstraints=critical,CA:TRUE',
             '-keyout',str(root/(name+'.key')),'-out',str(root/(name+'.pem'))])
    certs=root/'server';certs.mkdir();certs.chmod(0o755)
    run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=tls-db',
         '-keyout',str(certs/'server.key'),'-out',str(root/'server.csr')])
    (root/'extensions').write_text('subjectAltName=DNS:localhost,DNS:tls-db\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n')
    run(['openssl','x509','-req','-days','2','-in',str(root/'server.csr'),
         '-CA',str(root/'ca.pem'),'-CAkey',str(root/'ca.key'),'-CAcreateserial',
         '-extfile',str(root/'extensions'),'-out',str(certs/'server.crt')])
    (certs/'server.crt').chmod(0o644)


def connect(ca,port,host='localhost'):
    return psycopg.connect(host=host,hostaddr='127.0.0.1',port=port,user='postgres',
                          dbname='postgres',sslmode='verify-full',sslrootcert=str(ca),
                          connect_timeout=5,autocommit=True)


def main():
    run(D+['pull',IMAGE])
    name='brote-tls-'+uuid.uuid4().hex
    network=name+'-net'
    # Dedicated synthetic fixture network; only a loopback port is published for
    # host psycopg. Production restore containers remain entirely networkless.
    run(D+['network','create','--driver','bridge',network])
    scratch_base=Path(os.environ.get('RUNNER_TEMP',Path.cwd()/'work'))
    scratch_base.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='brote-tls-',dir=scratch_base) as scratch:
        root=Path(scratch)
        os.environ['RUNNER_TEMP']=str(root)
        try:
            certificates(root)
            command=('cp /certs/server.key /tmp/tls.key; chown postgres:postgres /tmp/tls.key; '
                     'chmod 600 /tmp/tls.key; exec docker-entrypoint.sh postgres '
                     '-c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/tmp/tls.key')
            run(D+['run','-d','--name',name,'--network',network,'--network-alias','tls-db',
                   '-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust',
                   '--mount',f'type=bind,src={root / "server"},dst=/certs,readonly',
                   '--entrypoint','bash',IMAGE,'-euc',command])
            for _ in range(60):
                try:
                    run(D+['exec',name,'pg_isready','-U','postgres']);break
                except RuntimeError:
                    if run(D+['inspect','--format','{{.State.Status}}',name]).strip()==b'exited':
                        raise RuntimeError('Synthetic PostgreSQL exited during startup') from None
                    time.sleep(1)
            else:raise RuntimeError('Synthetic PostgreSQL did not become ready')
            port=int(run(D+['inspect','--format',
                '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}',name]).decode())
            address=run(D+['inspect','--format',
                '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',name]).decode().strip()
            os.environ['BACKUP_PG_CA_PEM']=(root/'ca.pem').read_text()
            with database.postgres_ca() as ca:
                assert ca.stat().st_mode & 0o777 == 0o600
                with connect(ca,port) as conn:
                    conn.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
                    assert conn.execute('select 1').fetchone()==(1,)
                    snapshot=conn.execute('select pg_export_snapshot()').fetchone()[0]
                    env=dict(os.environ,PGHOST='tls-db',PGUSER='postgres',PGDATABASE='postgres',
                             PGPASSWORD='',PGSSLMODE='verify-full',PGSSLROOTCERT=str(ca),
                             PGCONNECT_TIMEOUT='5',PGOPTIONS='-c default_transaction_read_only=on',
                             PGHOSTADDR=address)
                    database.IMAGE=IMAGE
                    def dump(root_ca,hostname):
                        values=dict(env,PGSSLROOTCERT=str(root_ca),PGHOST=hostname)
                        args=database.dump_args(snapshot,values)
                        index=args.index('run')+1
                        args[index:index]=['--network',network,'-e','PGHOSTADDR']
                        set_stage('PG_DUMP')
                        return run(args,env=values)
                    assert dump(ca,'tls-db').startswith(b'PGDMP')
                    for root_ca,python_host,docker_host in [
                            (root/'untrusted.pem','localhost','tls-db'),
                            (ca,'wrong.invalid','wrong.invalid')]:
                        try:
                            with connect(root_ca,port,python_host):pass
                        except psycopg.OperationalError as error:
                            assert pg_category(str(error),error.sqlstate)=='PG_TLS_VERIFY'
                        else:raise AssertionError('Python accepted an invalid certificate')
                        try:dump(root_ca,docker_host)
                        except SafeFailure as error:assert error.category=='PG_TLS_VERIFY'
                        else:raise AssertionError('pg_dump accepted an invalid certificate')
            assert not ca.exists()
            for pem,category in [('', 'PG_CA_MISSING'),('not a certificate','PG_CA_INVALID')]:
                os.environ['BACKUP_PG_CA_PEM']=pem
                try:
                    with database.postgres_ca():pass
                except SafeFailure as error:assert error.category==category
                else:raise AssertionError('Invalid CA configuration accepted')
            print('PASS: psycopg and Docker pg_dump verify valid CA/hostname, reject wrong CA and wrong hostname; ephemeral CA cleanup and missing/malformed CA checks passed.')
        finally:
            run(D+['rm','-f',name])
            run(D+['network','rm',network])


if __name__=='__main__':main()
