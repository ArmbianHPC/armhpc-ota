# SPDX-License-Identifier: GPL-3.0-only
from copy import deepcopy
from pathlib import Path
import tarfile
from unittest import mock
import unittest

from armhpc_ota import framework_catalog, maintenance
from armhpc_ota.device import discover, layout
from armhpc_ota.io import atomic_json, read_json, sha256
from armhpc_ota.lan_publish import tools_bundle
import test_lan


class FrameworkCatalogMigration(unittest.TestCase):
    def setUp(self):
        test_lan.MaintenanceTests.setUp(self)
        self.payload = self.root/'pkg/armhpc-ota-0.3.0'
        self.names = ['usr/lib/armhpc/'+n+'.py' for n in ('swap_config', 'resource_config', 'kube_runtime')]
        rows = []
        for name in self.names:
            source = self.payload/'compat/framework/common'/Path(name).name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text('# authenticated new '+name+'\n')
            rows.append({'target': name, 'source': source.relative_to(self.payload).as_posix(),
                         'scope': 'common', 'sha256': sha256(source)})
        atomic_json(self.payload/'compat/framework-files.json', {'protocol': 1, 'files': rows})
        runtime = self.root/'framework-runtime.tar.xz'
        with tarfile.open(runtime, 'w:xz') as archive:
            for source in self.payload.rglob('*'):
                if source.is_file():
                    archive.add(source, arcname='armhpc-ota-0.3.0/'+source.relative_to(self.payload).as_posix())
        self.bundle = Path(tools_bundle(runtime, self.root/'framework-published', self.key, 'test')['bundle'])
        device = read_json(self.root/'device.json')
        for disk in device['blocks']:
            if disk.get('tran') == 'sata':
                disk.update(serial='catalog-fixture-disk', wwn='fixture-wwn')
        atomic_json(self.root/'device.json', device)
        storage = layout(self.c, discover(self.c), initialized=True)
        self.data = self.root/'roots/data'
        self.catalog = self.data/framework_catalog.CATALOG
        self.system = self.root/'roots/system'
        entries = []
        for name in self.names:
            target = self.system/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('# registered old '+name+'\n')
            target.chmod(0o644)
            checksum = sha256(target)
            cache = self.data/framework_catalog.RESOURCES/checksum
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_bytes(target.read_bytes())
            cache.chmod(0o600)
            entries.append({'path': name, 'sha256': checksum, 'mode': 0o644})
        self.before = {'schema_version': 1,
            'data': {'uuid': storage['partitions']['data']['uuid'],
                     'serial': 'catalog-fixture-disk', 'wwn': 'fixture-wwn'},
            'services': {'custom-bindings.service': {'enabled': True, 'version': None, 'files': entries}}}
        atomic_json(self.catalog, self.before)

    def install(self):
        maintenance.schedule(self.e, self.bundle)
        return maintenance.worker(self.e)['maintenance']

    def test_signed_update_refreshes_only_framework_code_and_retains_history(self):
        result = self.install()
        self.assertEqual('succeeded', result['stage'])
        after = read_json(self.catalog)
        self.assertEqual(self.before['data'], after['data'])
        for item in after['services']['custom-bindings.service']['files']:
            self.assertEqual(sha256(self.system/item['path']), item['sha256'])
            self.assertEqual(sha256(self.data/framework_catalog.RESOURCES/item['sha256']), item['sha256'])
            self.assertEqual(0o600, (self.data/framework_catalog.RESOURCES/item['sha256']).stat().st_mode & 0o777)
        backup = self.c.state/'maintenance/backups'/result['task_id']/'system'
        self.assertEqual(self.before, read_json(backup/'framework-catalog-before.json'))
        self.assertEqual(3, len(read_json(backup/'framework-catalog-update.json')['changes']))
        self.assertEqual('DATA-MUST-NOT-CHANGE', (self.root/'data/keep.txt').read_text())

    def test_unrelated_configuration_conflicts_are_not_accepted(self):
        state = deepcopy(self.before)
        old = self.data/framework_catalog.RESOURCES/('a'*64)
        old.write_text('original configuration')
        old.chmod(0o600)
        state['services']['custom-bindings.service']['files'].append({
            'path': 'etc/armhpc/custom.json', 'sha256': sha256(old), 'mode': 0o600})
        destination = self.system/'etc/armhpc/custom.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text('locally changed configuration')
        destination.chmod(0o600)
        atomic_json(self.catalog, state)
        self.assertEqual('succeeded', self.install()['stage'])
        after = read_json(self.catalog)['services']['custom-bindings.service']['files'][-1]
        self.assertEqual(state['services']['custom-bindings.service']['files'][-1], after)
        self.assertNotEqual(sha256(destination), after['sha256'])

    def test_damaged_original_recovery_copy_blocks_migration(self):
        original = self.before['services']['custom-bindings.service']['files'][0]
        (self.data/framework_catalog.RESOURCES/original['sha256']).write_text('damaged')
        result = self.install()
        self.assertEqual('incomplete', result['stage'])
        self.assertEqual('framework_state_hash', result['error']['code'])
        self.assertEqual(self.before, read_json(self.catalog))

    def test_wrong_data_identity_blocks_migration(self):
        invalid = deepcopy(self.before)
        invalid['data']['serial'] = 'different-disk'
        atomic_json(self.catalog, invalid)
        result = self.install()
        self.assertEqual('incomplete', result['stage'])
        self.assertEqual('framework_state_identity', result['error']['code'])
        self.assertEqual(invalid, read_json(self.catalog))

    def test_linked_catalog_cannot_modify_external_files(self):
        outside = self.root/'private-outside-catalog.json'
        self.catalog.rename(outside)
        self.catalog.symlink_to(outside)
        result = self.install()
        self.assertEqual('incomplete', result['stage'])
        self.assertEqual('framework_state_path', result['error']['code'])
        self.assertEqual(self.before, read_json(outside))

    def test_interruption_before_catalog_commit_resumes_original_migration(self):
        original = framework_catalog.atomic_copy
        def interrupted(source, destination, mode=0o600):
            if Path(destination) == self.catalog:
                raise OSError('simulated catalog commit interruption')
            return original(source, destination, mode)
        with mock.patch.object(framework_catalog, 'atomic_copy', side_effect=interrupted):
            first = self.install()
        self.assertEqual('incomplete', first['stage'])
        self.assertEqual(self.before, read_json(self.catalog))
        maintenance.schedule(self.e, self.bundle, request_id=first['task_id'])
        second = maintenance.worker(self.e)['maintenance']
        self.assertEqual('succeeded', second['stage'])
        self.assertEqual(first['task_id'], second['task_id'])
        self.assertNotEqual(self.before, read_json(self.catalog))

    def test_completed_migration_is_idempotent(self):
        result = self.install()
        before = self.catalog.read_bytes()
        payload = Path(maintenance.record(self.c)['payload'])
        files = maintenance.runtime_files(payload, 'arm64', 'system', self.c.profile)
        storage = layout(self.c, discover(self.c), initialized=True)
        backup = self.c.state/'maintenance/backups'/result['task_id']/'system'
        self.assertTrue(framework_catalog.rebase(self.e, storage, self.system, files, backup)['resumed'])
        self.assertEqual(before, self.catalog.read_bytes())

    def test_rollback_restores_old_code_and_catalog_as_a_pair(self):
        self.assertEqual('succeeded', self.install()['stage'])
        maintenance.schedule(self.e, rollback=True)
        self.assertEqual('rolled-back', maintenance.worker(self.e)['maintenance']['stage'])
        self.assertEqual(self.before, read_json(self.catalog))
        for item in self.before['services']['custom-bindings.service']['files']:
            self.assertEqual(item['sha256'], sha256(self.system/item['path']))

    def test_rollback_retains_unrelated_new_catalog_changes(self):
        self.assertEqual('succeeded', self.install()['stage'])
        after = read_json(self.catalog)
        after['services']['new-operator.service'] = {'enabled': False, 'files': []}
        atomic_json(self.catalog, after)
        maintenance.schedule(self.e, rollback=True)
        result = maintenance.worker(self.e)['maintenance']
        self.assertEqual('incomplete', result['stage'])
        self.assertEqual('framework_state_changed', result['error']['code'])
        self.assertEqual(after, read_json(self.catalog))


if __name__ == '__main__':
    unittest.main()
