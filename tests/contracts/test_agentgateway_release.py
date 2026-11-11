"""How scripts/agentgateway_release.py reads GitHub's replies, on canned data.

OFFLINE: nothing here calls GitHub. The shapes below are the fields the script uses from
the releases and security-advisories endpoints.
"""
import sys, unittest
from pathlib import Path

R = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(R / 'scripts'))
from agentgateway_release import affects, assess, parse  # noqa: E402


def release(tag, **over):
    return {'tag_name': tag, 'draft': False, 'prerelease': False, 'published_at': '2026-10-27T17:18:28Z',
            'html_url': 'https://example.invalid/' + tag, **over}


def advisory(*ranges, **over):
    return {'ghsa_id': 'GHSA-xxxx-xxxx-xxxx', 'state': 'published', 'severity': 'medium', 'summary': 'canned',
            'html_url': 'https://example.invalid/advisory',
            'vulnerabilities': [{'vulnerable_version_range': r, 'patched_versions': 'canned'} for r in ranges], **over}


class Versions(unittest.TestCase):
    def test_release_versions(self):
        self.assertEqual(parse('1.7.0'), (1, 7, 0))
        self.assertEqual(parse('v1.10.2'), (1, 10, 2))
        self.assertLess(parse('v1.9.0'), parse('v1.10.0'), 'compared as numbers, not as text')

    def test_everything_else_is_not_a_release(self):
        for tag in ['v1.8.0-rc.1', '1.8.0-alpha.1', 'v1.8', '1.8.0+build', 'V1.8.0', 'latest', '']:
            with self.subTest(tag=tag):
                self.assertIsNone(parse(tag))


class Releases(unittest.TestCase):
    def test_pinned_is_the_latest(self):
        result = assess('1.7.0', [release('v1.7.0'), release('v1.6.0'), release('v1.5.0')], [])
        self.assertEqual(result['newer'], [])
        self.assertEqual(result['latest']['tag'], 'v1.7.0')
        self.assertTrue(result['pinned_is_a_release_upstream'])

    def test_newer_releases_are_listed_oldest_first_whatever_the_order_of_the_reply(self):
        result = assess('1.7.0', [release('v1.7.0'), release('v1.10.0'), release('v1.7.1'), release('v1.8.0'), release('v1.6.0')], [])
        self.assertEqual([r['tag'] for r in result['newer']], ['v1.7.1', 'v1.8.0', 'v1.10.0'])
        self.assertEqual(result['latest']['tag'], 'v1.10.0')

    def test_pre_releases_and_drafts_do_not_count(self):
        replies = [release('v1.7.0'), release('v1.8.0-rc.1', prerelease=True), release('v1.8.0', draft=True),
                   release('v1.9.0', prerelease=True),
                   # upstream has published alpha and beta tags without the prerelease flag
                   release('v1.8.0-beta.1'), release('v1.8.0-alpha.2')]
        result = assess('1.7.0', replies, [])
        self.assertEqual(result['newer'], [])
        self.assertEqual(result['latest']['tag'], 'v1.7.0')

    def test_a_pin_that_upstream_does_not_have_is_reported(self):
        self.assertFalse(assess('1.7.3', [release('v1.7.0')], [])['pinned_is_a_release_upstream'])

    def test_the_pin_itself_must_be_a_release(self):
        with self.assertRaises(ValueError):
            assess('1.8.0-rc.1', [release('v1.7.0')], [])


class Advisories(unittest.TestCase):
    def test_ranges(self):
        pinned = (1, 7, 0)
        for text, expected in [('<v1.7.0', False), ('<1.7.0', False), ('< 1.8.0', True), ('<=1.7.0', True), ('= 1.7.0', True),
                               ('>= 1.5.0, < 1.7.0', False), ('>= 1.5.0, < 1.7.1', True), ('>=1.7.1,<1.9.0', False),
                               ('> 1.7.0', False), ('<v0.12.0', False)]:
            with self.subTest(range=text):
                self.assertIs(affects(text, pinned), expected)

    def test_a_range_that_cannot_be_read_is_neither_yes_nor_no(self):
        for text in ['', 'all versions', '< 1.8.0-rc.1', '~1.7', '<1.8.0 || >2.0.0']:
            with self.subTest(range=text):
                self.assertIsNone(affects(text, (1, 7, 0)))

    def test_only_advisories_that_include_the_pin_are_reported(self):
        fixed_in_the_pin, open_for_the_pin = advisory('<v1.7.0', ghsa_id='GHSA-old'), advisory('<v1.8.0', ghsa_id='GHSA-new')
        result = assess('1.7.0', [release('v1.7.0')], [fixed_in_the_pin, open_for_the_pin])
        self.assertEqual([a['id'] for a in result['advisories_affecting_the_pin']], ['GHSA-new'])
        self.assertEqual(result['advisories_with_a_range_not_understood'], [])

    def test_an_unreadable_range_is_reported_for_a_human_not_dropped(self):
        result = assess('1.7.0', [release('v1.7.0')], [advisory('all versions', ghsa_id='GHSA-odd'), advisory(ghsa_id='GHSA-empty')])
        self.assertEqual(result['advisories_affecting_the_pin'], [])
        self.assertEqual([a['id'] for a in result['advisories_with_a_range_not_understood']], ['GHSA-odd', 'GHSA-empty'])

    def test_one_affected_package_is_enough(self):
        result = assess('1.7.0', [release('v1.7.0')], [advisory('<v1.6.0', '<v1.9.0')])
        self.assertEqual(len(result['advisories_affecting_the_pin']), 1)

    def test_advisories_that_are_not_published_are_ignored(self):
        result = assess('1.7.0', [release('v1.7.0')], [advisory('<v1.9.0', state='draft'), advisory('<v1.9.0', state='withdrawn')])
        self.assertEqual(result['advisories_affecting_the_pin'], [])


if __name__ == '__main__':
    unittest.main()
