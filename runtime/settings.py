"""Private configuration lives exclusively in Environment Secrets, never in this kit."""
import json
import os
import re


def config():
    try:
        value = json.loads(os.environ['BACKUP_CONFIG'])
        for key in ('controller_repository', 'vault_repository', 'source_repository'):
            if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value[key]):
                raise ValueError()
        if len({value[k] for k in ('controller_repository','vault_repository','source_repository')}) != 3:
            raise ValueError()
        owner = value['controller_repository'].split('/')[0]
        if any(value[k].split('/')[0] != owner for k in ('vault_repository','source_repository')):
            raise ValueError()
        if not re.fullmatch(r'[a-z]{20}', value['project_ref']):
            raise ValueError()
        rehearsal = value['rehearsal']
        if not re.fullmatch(r'[a-f0-9]{40}', rehearsal['ref']):
            raise ValueError()
        if not re.fullmatch(r'[a-f0-9]{64}', rehearsal['sha256']):
            raise ValueError()
        if rehearsal['path'].startswith('/') or '..' in rehearsal['path'].split('/'):
            raise ValueError()
        return value
    except (KeyError, ValueError, TypeError):
        raise RuntimeError('Private configuration is missing or invalid') from None


def controller_repo():
    return config()['controller_repository']


def vault_repo():
    return config()['vault_repository']


def source_repo():
    return config()['source_repository']


def mask_private_config():
    """Defense in depth: do not rely on GitHub masking fragments of JSON secrets."""
    value = config()
    for key in ('vault_repository','source_repository','project_ref'):
        print('::add-mask::' + value[key], flush=True)
