#!/usr/bin/env python3
"""Regression tests for trusted, content-addressed vendor approvals."""

import subprocess
import unittest
from unittest.mock import patch

import pr_policy


class VendorApprovalTests(unittest.TestCase):
    BASE = "1" * 40
    HEAD = "2" * 40
    ROOT = "vendor/wreq-util"
    TREE = "30aad1fc36154d6013974f822b9e74de48012a85"

    def check_vendor(self, root, tree=None, exists=False):
        errors = []
        result = subprocess.CompletedProcess([], 0 if exists else 1)
        with patch.object(pr_policy.subprocess, "run", return_value=result), patch.object(
            pr_policy, "git", return_value=f"{tree}\n"
        ) as git:
            pr_policy.check_new_vendor(
                self.BASE, self.HEAD, [f"{root}/Cargo.toml"], errors
            )
            return errors, git.call_args_list

    def test_only_reviewed_tree_is_approved(self):
        self.assertEqual(pr_policy.APPROVED_NEW_VENDOR_TREES, {self.ROOT: self.TREE})
        errors, calls = self.check_vendor(self.ROOT, self.TREE)
        self.assertEqual(errors, [])
        self.assertEqual(
            calls, [unittest.mock.call("rev-parse", f"{self.HEAD}:{self.ROOT}", text=True)]
        )

    def test_modified_approved_tree_is_rejected(self):
        errors, _ = self.check_vendor(self.ROOT, "3" * 40)
        self.assertEqual(len(errors), 1)
        self.assertIn("requires explicit maintainer handling", errors[0])

    def test_other_new_dependency_is_rejected(self):
        errors, calls = self.check_vendor("vendor/unapproved", self.TREE)
        self.assertEqual(len(errors), 1)
        self.assertEqual(calls, [])

    def test_similar_dependency_name_is_rejected(self):
        errors, _ = self.check_vendor("vendor/wreq-util-extra", self.TREE)
        self.assertEqual(len(errors), 1)

    def test_existing_dependency_keeps_current_policy(self):
        errors, calls = self.check_vendor("vendor/taffy", exists=True)
        self.assertEqual(errors, [])
        self.assertEqual(calls, [])

    def test_git_failure_does_not_allow_dependency(self):
        result = subprocess.CompletedProcess([], 1)
        with patch.object(pr_policy.subprocess, "run", return_value=result), patch.object(
            pr_policy, "git", side_effect=subprocess.CalledProcessError(128, ["git"])
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                pr_policy.check_new_vendor(
                    self.BASE, self.HEAD, [f"{self.ROOT}/Cargo.toml"], []
                )


if __name__ == "__main__":
    unittest.main()
