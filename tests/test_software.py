# SPDX-License-Identifier: GPL-3.0-only
import unittest
from armhpc_ota.backend import verify_software_plan, software_install_arguments
from armhpc_ota.errors import OTAError


class SoftwareResourcesTests(unittest.TestCase):
    def test_apt_solver_success_does_not_hide_uncached_dependencies(self):
        verify_software_plan('Inst example (1.0 local [arm64])\n', {('example', '1.0')})
        with self.assertRaises(OTAError):
            verify_software_plan('Inst example (1.0 local [arm64])\nInst dependency [2.0] (1.0 repo [arm64])\n',
                                 {('example', '1.0')})

    def test_missing_resources_report_exact_packages_and_versions(self):
        with self.assertRaises(OTAError) as raised:
            verify_software_plan('Inst ipvsadm (1:1.31-1 repo [arm64])\n'
                                 'Inst libxml2 [old] (2.9.14+dfsg-1.3~deb12u6 repo [arm64])\n', set())
        self.assertIn('ipvsadm=1:1.31-1', str(raised.exception))
        self.assertEqual(raised.exception.details['missing_packages'], [
            {'package':'ipvsadm','version':'1:1.31-1'},
            {'package':'libxml2','version':'2.9.14+dfsg-1.3~deb12u6'}])

    def test_unparsed_install_is_not_silently_accepted(self):
        with self.assertRaises(OTAError) as raised:
            verify_software_plan('Inst unexpected-output\n', set())
        self.assertEqual(raised.exception.details['reason'], 'unparsed_install')

    def test_restore_and_simulation_share_recommendation_policy(self):
        for simulate in (False, True):
            args=software_install_arguments(['/cache/old.deb'],simulate=simulate)
            self.assertIn('--no-install-recommends',args)
            self.assertIn('--no-remove',args)
            self.assertEqual(args[-2:],['install','/cache/old.deb'])
            self.assertEqual('-s' in args,simulate)
            self.assertEqual('--no-download' in args,not simulate)
