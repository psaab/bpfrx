#!/usr/bin/env python3
"""Unit tests for validate.py run-ID namespacing + ownership-gated deletion
(#4905-D).

validate.py boots the baked image under LOCAL incus. Before the fix the alias
(`xpf-image-validate`) and every scenario instance (`xpf-image-a`..`e`) were
CONSTANTS, force-deleted at import/launch/cleanup with no lock/run-ID/ownership
tag — so a concurrent bake, or an unrelated same-named VM/image, was silently
destroyed.

The fix namespaces the alias + instances with a process-unique run-ID, tags
every instance it creates with `user.xpf-owner=<run_id>`, and refuses to delete
any object that does not carry THIS run's tag. These tests assert:

  - alias + instance names are run-namespaced (two runs never collide);
  - _owned_delete() DELETES an instance tagged with this run_id;
  - _owned_delete() REFUSES an instance with a foreign tag (or no instance);
  - launch() tags the instance with user.xpf-owner=<run_id>;
  - cleanup() deletes the alias only when THIS run imported it, and only the
    namespaced alias — never a bystander's `xpf-image-validate`.

RED on revert: restore the constant ALIAS + unconditional `incus delete -f`
and the foreign-tag deletion is no longer refused — the assertions flip.
"""

from __future__ import annotations

import importlib.util
import types
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "validate", Path(__file__).with_name("validate.py"))
validate = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(validate)


class _IncusRecorder:
    """Records incus() calls; canned reply for `config get user.xpf-owner`."""

    def __init__(self, owner_tag="", get_rc=0):
        self.calls = []
        self.owner_tag = owner_tag
        self.get_rc = get_rc

    def __call__(self, *args, check=True, capture=False):
        self.calls.append(tuple(args))
        if args[:2] == ("config", "get"):
            return types.SimpleNamespace(returncode=self.get_rc,
                                         stdout=self.owner_tag, stderr="")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    def deletes(self):
        return [c for c in self.calls if c[:1] == ("delete",)]

    def image_deletes(self):
        return [c for c in self.calls if c[:2] == ("image", "delete")]

    def inits(self):
        return [c for c in self.calls if c[:1] == ("init",)]


def _harness(keep=False):
    return validate.Harness("img.qcow2", "meta.tar.gz", "xpf-image-net", keep)


class NamespacingTests(unittest.TestCase):
    def test_alias_is_run_namespaced(self):
        h = _harness()
        self.assertTrue(h.alias.startswith(validate.ALIAS + "-"))
        self.assertNotEqual(h.alias, validate.ALIAS)

    def test_instance_names_are_run_namespaced(self):
        h = _harness()
        self.assertIn(h.run_id, h.iname("a"))
        self.assertTrue(h.iname("a").startswith("xpf-image-"))
        self.assertNotEqual(h.iname("a"), "xpf-image-a")

    def test_two_runs_do_not_collide(self):
        self.assertNotEqual(_harness().run_id, _harness().run_id)


class OwnedDeleteTests(unittest.TestCase):
    def test_deletes_instance_tagged_with_this_run(self):
        h = _harness()
        rec = _IncusRecorder(owner_tag=h.run_id + "\n", get_rc=0)
        with mock.patch.object(validate, "incus", rec):
            h._owned_delete("xpf-image-x")
        self.assertEqual(rec.deletes(), [("delete", "-f", "xpf-image-x")],
                         "an instance carrying THIS run's tag must be deleted")

    def test_refuses_foreign_tagged_instance(self):
        h = _harness()
        rec = _IncusRecorder(owner_tag="some-other-run\n", get_rc=0)
        with mock.patch.object(validate, "incus", rec):
            h._owned_delete("xpf-image-a")   # the OLD constant name
        self.assertEqual(rec.deletes(), [],
                         "an un-owned instance must NOT be force-deleted (#4905-D)")

    def test_refuses_untagged_instance(self):
        h = _harness()
        rec = _IncusRecorder(owner_tag="", get_rc=0)  # tag present but empty
        with mock.patch.object(validate, "incus", rec):
            h._owned_delete("bystander-vm")
        self.assertEqual(rec.deletes(), [])

    def test_missing_instance_is_a_noop(self):
        h = _harness()
        rec = _IncusRecorder(owner_tag="", get_rc=1)  # `config get` fails => absent
        with mock.patch.object(validate, "incus", rec):
            h._owned_delete("does-not-exist")
        self.assertEqual(rec.deletes(), [])


class LaunchTagTests(unittest.TestCase):
    def test_launch_tags_instance_with_owner(self):
        h = _harness()
        rec = _IncusRecorder(owner_tag="", get_rc=1)  # pre-delete finds nothing
        name = h.iname("a")
        with mock.patch.object(validate, "incus", rec):
            with mock.patch.object(h, "wait_agent", return_value=None):
                h.launch(name)
        inits = rec.inits()
        self.assertEqual(len(inits), 1)
        self.assertIn(f"user.xpf-owner={h.run_id}", inits[0],
                      "launched instance must carry this run's ownership tag")
        self.assertIn(h.alias, inits[0],
                      "launch must init from the run-namespaced alias")


class CleanupTests(unittest.TestCase):
    def test_cleanup_deletes_only_imported_namespaced_alias(self):
        h = _harness()
        h.imported_alias = True
        h.instances = []
        h.created_net = False
        rec = _IncusRecorder()
        with mock.patch.object(validate, "incus", rec):
            with mock.patch.object(validate.subprocess, "run",
                                   return_value=types.SimpleNamespace(returncode=0)):
                h.cleanup()
        self.assertIn(("image", "delete", h.alias), rec.image_deletes())
        # It must NEVER delete a bystander's constant `xpf-image-validate`.
        self.assertNotIn(("image", "delete", validate.ALIAS), rec.image_deletes())

    def test_cleanup_skips_alias_it_did_not_import(self):
        h = _harness()
        h.imported_alias = False   # we never imported an alias this run
        h.instances = []
        h.created_net = False
        rec = _IncusRecorder()
        with mock.patch.object(validate, "incus", rec):
            with mock.patch.object(validate.subprocess, "run",
                                   return_value=types.SimpleNamespace(returncode=0)):
                h.cleanup()
        self.assertEqual(rec.image_deletes(), [],
                         "cleanup must not delete an alias this run did not import")


if __name__ == "__main__":
    unittest.main()
