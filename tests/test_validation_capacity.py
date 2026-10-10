# SPDX-License-Identifier: GPL-3.0-only
import unittest
from armhpc_ota.backend import validation_copy_size
from armhpc_ota.errors import OTAError

class ValidationCapacityTests(unittest.TestCase):
    def test_conservative_estimate_may_use_remaining_target_space(self):
        # A compact ext4's unused blocks were formerly added to the preserved
        # byte estimate and caused a false rejection of the original slot size.
        capacity = 1958723072
        size = validation_copy_size(1288708096, 560 * 1024**2, 0, capacity)
        self.assertEqual(capacity // 4096 * 4096, size)

    def test_signed_image_larger_than_target_still_rejected(self):
        with self.assertRaises(OTAError):
            validation_copy_size(128 * 1024**2, 0, 0, 64 * 1024**2)

    def test_small_preservation_does_not_expand_to_a_full_64g(self):
        size = validation_copy_size(256 * 1024**2, 16 * 1024**2, 0, 64 * 1024**3)
        self.assertEqual(400 * 1024**2, size)
