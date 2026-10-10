# SPDX-License-Identifier: GPL-3.0-only
import unittest
from armhpc_ota.backend import verify_software_plan
from armhpc_ota.errors import OTAError


class SoftwareResourcesTests(unittest.TestCase):
    def test_apt_solver_success_does_not_hide_uncached_dependencies(self):
        verify_software_plan('Inst example (1.0 local [arm64])\n', {('example', '1.0')})
        with self.assertRaises(OTAError):
            verify_software_plan('Inst example (1.0 local [arm64])\nInst dependency [2.0] (1.0 repo [arm64])\n',
                                 {('example', '1.0')})
