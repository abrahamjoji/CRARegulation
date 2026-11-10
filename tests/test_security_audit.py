"""Regression checks for untrusted evidence and concurrent hosted work."""
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
from cra.common.bundle import write_manifest, verify_manifest, verify_evidence_references
from cra.common.errors import CraError, UntrustedInputError
from cra.engine.policy import _validated, SCHEMA
from cra.hosted.db import Database, Principal


class EvidenceSecurity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'evidence').mkdir()
        (self.root / 'evidence/data').write_text('safe')
        self.manifest = write_manifest(self.root)

    def test_nested_manifest_is_covered(self):
        (self.root / 'evidence/manifest.json').write_text('{}')
        self.assertIn('unlisted: evidence/manifest.json', verify_manifest(self.root))

    def test_reference_cannot_escape_verified_bundle(self):
        collection = {'evidence': [{'id': 'evil', 'path': '../secret'}], 'observations': [], 'artifacts': []}
        with self.assertRaises(UntrustedInputError):
            verify_evidence_references(self.root, collection)

    def test_reference_must_match_manifest_hash(self):
        record = dict(self.manifest['files'][0], id='ev')
        record['sha256'] = '0' * 64
        with self.assertRaises(UntrustedInputError):
            verify_evidence_references(self.root, {'evidence': [record], 'observations': [], 'artifacts': []})

    def test_symlink_manifest_rejected(self):
        (self.root / 'manifest.json').rename(self.root / 'saved')
        (self.root / 'manifest.json').symlink_to(self.root / 'saved')
        with self.assertRaises(UntrustedInputError):
            verify_manifest(self.root)

    def test_invalid_policy_values_fail_closed(self):
        for section, key, value in [('build', 'block_kev_untriaged', 'false'), ('freshness', 'max_kev_age_hours', float('nan')), ('freshness', 'max_kev_age_hours', float('inf')), ('triage', 'max_investigation_days', -1), ('vex', 'trusted_authors', 'anyone')]:
            with self.subTest(key=key, value=value), self.assertRaises(CraError):
                _validated({'schema_version': SCHEMA, 'version': 'test', section: {key: value}}, 'test')


class HostedConcurrency(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Database(Path(self.temp.name) / 'db.sqlite')
        self.db.initialize()
        tenant = self.db.create_tenant('tenant')
        project = self.db.create_project(tenant, 'project')
        self.principal = Principal(tenant, project, 'test', frozenset())

    def create(self, key='key', **kwargs):
        return self.db.create_job(self.principal, key, 'a' * 64, 10, 1, **kwargs)[0]

    def test_upload_is_published_before_job_becomes_visible(self):
        seen = []
        def publish(identifier):
            seen.append(identifier)
            self.assertIsNone(self.db.get_job(self.principal, identifier))
        job = self.create(publish=publish)
        self.assertEqual(seen, [job['id']])
        self.assertIsNotNone(self.db.get_job(self.principal, job['id']))

    def test_failed_publish_rolls_back_queue(self):
        def publish(_):
            raise OSError('disk full')
        with self.assertRaises(OSError):
            self.create(publish=publish)
        self.assertIsNone(self.db.claim_job(60, 3))

    def test_stale_worker_cannot_finish_publish_or_requeue(self):
        self.create()
        first = self.db.claim_job(-10, 3)
        second = self.db.claim_job(60, 3)
        published = []
        self.assertFalse(self.db.finish_job(first, 'completed', publish=lambda: published.append(True)))
        self.db.requeue(first)
        self.assertEqual(self.db.get_job(self.principal, first['id'])['status'], 'running')
        self.assertEqual(published, [])
        self.assertTrue(self.db.finish_job(second, 'completed', publish=lambda: published.append(True)))
        self.assertEqual(published, [True])

    def test_retry_obeys_active_job_limit(self):
        self.create()
        job = self.db.claim_job(60, 3)
        self.db.finish_job(job, 'failed')
        self.create('another')
        with self.assertRaises(OverflowError):
            self.create()


class ClientSecurity(unittest.TestCase):
    def test_url_rejects_query_fragment_and_controls(self):
        from cra.collector.hosted_client import check_url
        for url in ('https://example.com/?token=x', 'https://example.com/#frag', 'https://example.com/\n'):
            with self.subTest(url=url), self.assertRaises(CraError):
                check_url(url)

    def test_service_json_must_be_object(self):
        import io
        from unittest.mock import patch
        from cra.collector.hosted_client import request
        response = io.BytesIO(b'[]')
        response.status = 200
        with patch('cra.collector.hosted_client._OPENER.open', return_value=response):
            with self.assertRaises(CraError):
                request('GET', 'https://example.com', 'token')

    def test_gate_rejects_nan_age(self):
        from cra.gate import evaluate_gate
        self.assertEqual(evaluate_gate('/missing', max_age_hours=float('nan'))['outcome'], 'incomplete')
