"""Public date-only heartbeat. No environments, PATs, database or private configuration."""
import datetime
import os
from core import GitHub


def main():
    repo=os.environ['GITHUB_REPOSITORY']
    if repo != 'Parnufas/brote-backup-bot' or os.environ['GITHUB_REF'] != 'refs/heads/main':
        raise RuntimeError('Unexpected repository or branch')
    if os.environ['GITHUB_SHA'] != os.environ['BACKUP_APPROVED_SHA']:
        raise RuntimeError('Unapproved code')
    api=GitHub(os.environ['GITHUB_TOKEN'])
    branch='automation-heartbeat'
    try:
        api.call(f'repos/{repo}/git/ref/heads/{branch}')
    except RuntimeError as error:
        if str(error) != 'GitHub GET failed (404)':raise
        api.call(f'repos/{repo}/git/refs','POST',{'ref':'refs/heads/'+branch,'sha':os.environ['GITHUB_SHA']})
    import base64
    content=base64.b64encode((datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m')+'\n').encode()).decode()
    body={'message':'Monthly public scheduler heartbeat','branch':branch,'content':content}
    try:
        current=api.call(f'repos/{repo}/contents/HEARTBEAT?ref={branch}')
        if current['content'].strip()==content:return
        body['sha']=current['sha']
    except RuntimeError as error:
        if str(error) != 'GitHub GET failed (404)':raise
    api.call(f'repos/{repo}/contents/HEARTBEAT','PUT',body)


if __name__=='__main__':main()
