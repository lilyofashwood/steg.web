"""Run with python3 -m unittest test_preview -v. No providers or accounts."""

from http.client import HTTPConnection
from pathlib import Path
import tempfile
import threading
import unittest
import re
import unicodedata
import json
from urllib.parse import urlsplit

import preview

class QuietHandler(preview.ReviewHandler):
    def log_message(self, *args):
        pass

class PreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = preview.ThreadingHTTPServer(('127.0.0.1', 0), QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, route, method='GET', headers=None):
        conn = HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        conn.request(method, route, headers=headers or {})
        response = conn.getresponse()
        status, body, response_headers = response.status, response.read(), dict(response.getheaders())
        conn.close()
        return status, body, response_headers

    def test_all_literal_assets_exist_and_are_served(self):
        self.assertEqual(13, len(preview.APPS))
        self.assertEqual(101, len(preview.ALLOWED))
        for route, file in preview.ALLOWED.items():
            with self.subTest(route=route):
                status, body, headers = self.request(route)
                self.assertEqual(200, status)
                self.assertEqual(file.read_bytes(), body)
                self.assertEqual('nosniff', headers['X-Content-Type-Options'])

    def test_private_source_and_path_traversal_are_denied(self):
        paths = ('/.git/config', '/README.md', '/preview.py', '/background/', '/audits/', '/archive/',
                 '/apps/chatlog-printer/README.md', '/apps/hexmoji/archive/recovered/hexmoji.py',
                 '/apps/melody-cipher/historical/index.html', '/apps/twitterpainted/tests/fixture.png',
                 '/apps/font-garden/font-registry-v0_2.json', '/apps/ghost-hex/image.png/extra',
                 '/../workspace-context/README.md', '/%2e%2e/workspace-context/README.md',
                 '/apps/hexmoji/%2e%2e/index.html', '/apps/hexmoji/%252e%252e/index.html',
                 '/apps/hexmoji/..%5cREADME.md', '/apps/hexmoji/index.html%00',
                 '//example.com/', 'http://example.com/', '/apps/hexmoji/%ff')
        for route in paths:
            with self.subTest(route=route):
                self.assertIn(self.request(route)[0], (403, 404))

    def test_unexpected_host_fails_closed(self):
        for host in ('example.com', 'example.com:8779', '127.0.0.1', 'localhost:1'):
            with self.subTest(host=host):
                self.assertEqual(403, self.request('/', headers={'Host': host})[0])

    def test_writes_are_not_supported(self):
        for method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            self.assertEqual(501, self.request('/', method=method)[0])

    def test_head_and_version_query(self):
        status, body, headers = self.request('/apps/twitterpainted/twitterpainted.js?v=review', 'HEAD')
        self.assertEqual(200, status)
        self.assertEqual(b'', body)
        self.assertTrue(headers['Content-Type'].startswith('text/javascript'))
        self.assertGreater(int(headers['Content-Length']), 0)

    def test_allowlist_symlink_replacement_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target.html'
            target.write_text('test fixture', encoding='utf-8')
            link = Path(directory) / 'link.html'
            link.symlink_to(target)
            preview.ALLOWED['/test-symlink.html'] = link
            try:
                self.assertEqual(404, self.request('/test-symlink.html')[0])
            finally:
                del preview.ALLOWED['/test-symlink.html']

    def test_security_policy_blocks_remote_subresources(self):
        _, _, headers = self.request('/')
        policy = headers['Content-Security-Policy']
        for directive in ("connect-src 'self'", "font-src 'self' data:", "object-src 'none'", "frame-ancestors 'none'"):
            self.assertIn(directive, policy)
        self.assertNotIn('https:', policy)
        self.assertEqual('camera=(), microphone=(), geolocation=()', headers['Permissions-Policy'])

    def test_current_names_and_retired_routes(self):
        self.assertIn('uniception', preview.APPS)
        self.assertEqual('steg-web', preview.APPS['uniception'][0])
        self.assertIn('kagami-no-migaka', preview.APPS)
        self.assertEqual('kasane-uta', preview.APPS['kagami-no-migaka'][0])
        self.assertNotIn('kasane-uta', preview.APPS)
        self.assertNotIn('steg-web', preview.APPS)
        self.assertNotIn('veilscript-lab', preview.APPS)
        self.assertEqual(200, self.request('/apps/uniception/')[0])
        self.assertEqual(200, self.request('/apps/kagami-no-migaka/')[0])
        for route in ('/apps/kanotokoyo/', '/apps/migaka/', '/apps/kasane-uta/', '/apps/steg-web/', '/apps/veilscript-lab/', '/apps/veilscript-lab/core.js', '/archive/retired/veilscript-lab/index.html'):
            self.assertEqual(404, self.request(route)[0])

    def test_only_preserved_bloom_workshop_allows_same_origin_framing(self):
        framed = '/apps/diacritic-bloom/diacritic-bloom.html'
        for route in ('/', '/apps/diacritic-bloom/', framed,
                      '/apps/diacritic-bloom/presentation.js', '/apps/ouroboros-cipher/', '/README.md'):
            with self.subTest(route=route):
                policy = self.request(route)[2]['Content-Security-Policy']
                self.assertIn("frame-ancestors 'self'" if route == framed else "frame-ancestors 'none'", policy)
                self.assertNotIn('https:', policy)

    def test_dashboard_names_origin_map_and_poem_match(self):
        html = (preview.ROOT / 'index.html').read_text(encoding='utf-8')
        readme = (preview.ROOT / 'README.md').read_text(encoding='utf-8')
        self.assertEqual(13, html.count('<article class="card"'))
        self.assertIn('href="https://github.com/lilyofashwood"', html)
        self.assertIn('https://github.com/lilyofashwood/uniception', html)
        self.assertIn('https://github.com/lilyofashwood/kagami-no-migaka', html)
        self.assertIn('<h2>Kagami-no-Migaka</h2>', html)
        self.assertIn('かがみのしきしのみがか', html)
        self.assertNotIn('Replacement name pending', html)
        self.assertNotIn('<h2>Migaka</h2>', html)
        self.assertNotIn('href="https://github.com/lilyofashwood/kasane-uta"', html)
        self.assertNotIn('ashwood-archive', html)
        self.assertNotIn('href="/apps/veilscript-lab/', html)
        self.assertIn('<h1 aria-label="steg.web">𝗌𝗍𝐞𝗀.𝗐𝐞𝖻</h1>', html)
        origin_keys = set(re.findall(r'^  "([a-z-]+)": \[', html, re.MULTILINE))
        self.assertEqual(set(preview.APPS), origin_keys)
        poem = re.search(r'<!-- spider-poem:original:start -->\n<!--\n(.*?)\n-->\n<!-- spider-poem:original:end -->', readme, re.DOTALL).group(1)
        self.assertEqual(poem.splitlines(), [
            'the spider waits in silence still', 'its threads connect the dreaming dark',
            'a child calls out across the weave', 'and something ancient starts to hum',
            'two lonely things begin to play', 'but first it takes her breath away',
            'frozen when she tries to run', 'its a silken melody has stung',
        ])
        self.assertIn('steg.web', unicodedata.normalize('NFKC', readme.splitlines()[0]))

    def test_house_presentation_keeps_exact_poem_and_literal_commands(self):
        html = (preview.ROOT / 'index.html').read_text(encoding='utf-8')
        readme = (preview.ROOT / 'README.md').read_text(encoding='utf-8')
        original = re.search(r'<!-- spider-poem:original:start -->\n<!--\n(.*?)\n-->\n<!-- spider-poem:original:end -->', readme, re.DOTALL).group(1)
        poem = re.search(r'<p id="spider-poem-plain" class="poem-verses">(.*?)</p>', html, re.DOTALL).group(1)
        self.assertEqual(original.encode('utf-8'), poem.encode('utf-8'))
        self.assertEqual(8, len(poem.splitlines()))
        self.assertIn('aria-labelledby="spider-poem-title"', html)
        self.assertNotIn('archive/source-drop', html)
        self.assertIn('not a newly encoded payload', html)
        self.assertIn("'aeiou'.includes(lower)?0x1D41A:0x1D5BA", html)
        self.assertIn("voice==='mono'", html)
        self.assertIn("voice==='double'", html)
        self.assertIn("voice==='script'", html)
        self.assertIn("visible.setAttribute('aria-hidden','true')", html)
        self.assertIn("accessible.textContent=plain", html)
        self.assertIn("element.setAttribute('aria-label',plain)", html)
        self.assertIn("search.value.normalize('NFKC')", html)
        self.assertIn('card.dataset.slug=slug', html)
        self.assertIn("const searchable=card.dataset.slug+' '+card.textContent", html)
        self.assertIn("searchable.normalize('NFKC').toLocaleLowerCase().includes(q)", html)
        commands = re.findall(r'<pre>(.*?)</pre>', html, re.DOTALL)
        self.assertEqual([
            'python3 workspace-context/preview.py',
            'python3 chatlog-printer/scripts/serve-demo.py --port 8765\n'
            'melody-cipher/.venv/bin/python melody-cipher/studio.py --port 8766\n'
            'python3 steg-web/server.py --port 8768\n'
            'python3 kasane-uta/server.py --port 8767',
        ], commands)
        self.assertTrue(all(command.isascii() for command in commands))

    def test_complete_narrative_pass_protects_accessible_and_literal_text(self):
        html = (preview.ROOT / 'index.html').read_text(encoding='utf-8')
        self.assertIn('document.createTreeWalker(root,NodeFilter.SHOW_TEXT', html)
        self.assertIn('script,style,code,pre,.sr-only,.house-visible,[aria-hidden="true"],[data-literal]', html)
        self.assertIn("dressNarrative(document.querySelector('main'))", html)
        self.assertLess(html.index("card.querySelector('h2').after(note)"),
                        html.index("dressNarrative(document.querySelector('main'))"))
        self.assertIn('search.placeholder=houseText(search.placeholder)', html)
        self.assertIn('document.title=houseText(document.title)', html)
        self.assertNotIn('search.value=houseText', html)
        self.assertIn('code.textContent=match[0]', html)
        self.assertIn("projects open for exploration';dressLabel(count)", html)

    def test_public_catalog_excludes_private_sources_and_labels_unverified_pages(self):
        html = (preview.ROOT / 'index.html').read_text(encoding='utf-8')
        self.assertNotIn('snowline-mirrorfall', preview.APPS)
        self.assertNotIn('library-cellar', preview.APPS)
        self.assertNotIn('catilligraphy', preview.APPS)
        for path in ['/apps/snowline-mirrorfall/', '/apps/library-cellar/', '/apps/catilligraphy/',
                     '/apps/uniception/variants/snowline-mirrorfall/index.html',
                     '/apps/uniception/variants/snowline-mirrorfall/README.md',
                     '/apps/uniception/variants/snowline-mirrorfall/historical/landslide_mirrorfall_360.html']:
            self.assertEqual(404, self.request(path)[0])
        for forbidden in ['archive/source-drop', 'archive/private-continuations', 'catilligraphy', 'library-cellar',
                          'href="/apps/uniception/variants/snowline-mirrorfall/index.html']:
            self.assertNotIn(forbidden, html)
        pages = re.findall(r"^  '([^']+)':\{url:'([^']+)',verified:(true|false)\}", html, re.MULTILINE)
        self.assertEqual(set(preview.APPS), {slug for slug, _, _ in pages})
        self.assertEqual({'ghost-hex', 'twitterpainted', 'zalgo-cipher', 'ouroboros-cipher',
                          'chatlog-printer', 'melody-cipher', 'moon-tears', 'hexmoji', 'font-garden', 'diacritic-bloom', 'uniception', 'kagami-no-migaka'},
                         {slug for slug, _, verified in pages if verified=='true'})
        self.assertIn('Source-only · no hosted installer or demo', html)
        self.assertIn("site.verified?'Open live page':'Open repository'", html)
        self.assertIn("document.documentElement.dataset.previewMode=localPreview?'local':'public'", html)
        for name in ['ouroboros-cipher', 'zalgo-cipher', 'twitterpainted', 'messageloggerfix']:
            self.assertNotIn('href="https://github.com/lilyofashwood/'+name+'-review"', html)
            self.assertIn('href="https://github.com/lilyofashwood/'+name+'"', html)


    def test_public_variants_are_exact_allowlisted_adapters(self):
        for route in (
            '/apps/uniception/variants/snowline-mirrorfall/demo.html',
            '/apps/uniception/variants/snowline-mirrorfall/core.js',
            '/apps/uniception/variants/snowline-mirrorfall/specimen.js',
            '/apps/uniception/variants/snowline-mirrorfall/demo.js',
            '/apps/uniception/variants/snowline-mirrorfall/demo.css',
            '/apps/uniception/variants/nekomata-thread/index.html',
            '/apps/uniception/variants/nekomata-thread/app.js',
            '/apps/uniception/variants/nekomata-thread/specimen.js',
            '/apps/uniception/variants/nekomata-thread/style.css',
        ):
            with self.subTest(route=route):
                self.assertEqual(200, self.request(route)[0])
        for route in (
            '/apps/uniception/variants/nekomata-thread/tests/specimen.test.mjs',
            '/apps/uniception/variants/snowline-mirrorfall/public-source.json',
            '/apps/uniception/historical/stegweb-suite.py',
            '/apps/kagami-no-migaka/historical/recovered-design.md',
        ):
            self.assertEqual(404, self.request(route)[0])

    def test_variant_catalog_covers_every_project_and_only_safe_public_routes(self):
        html = (preview.ROOT / 'index.html').read_text(encoding='utf-8')
        catalog = json.loads(re.search(r'<script type="application/json" id="variant-catalog">\s*(.*?)\s*</script>', html, re.DOTALL).group(1))
        self.assertEqual(set(preview.APPS), set(catalog))
        counts = {}
        for slug, project in catalog.items():
            entries = [entry for group in project['groups'] for entry in group['entries']]
            self.assertTrue(project['note'])
            self.assertEqual(len(entries), len({entry['path'] for entry in entries}))
            counts[slug] = len(entries)
            for entry in entries:
                with self.subTest(slug=slug, path=entry['path']):
                    parsed = urlsplit(entry['path'])
                    if entry['kind'] == 'public':
                        self.assertFalse(parsed.scheme or parsed.netloc)
                        self.assertNotIn('..', parsed.path)
                        route = '/apps/' + slug + '/' + parsed.path
                        self.assertIn(route, preview.ALLOWED)
                        self.assertEqual(200, self.request(route + ('?' + parsed.query if parsed.query else ''))[0])
                    elif entry['kind'] == 'local':
                        self.assertEqual('melody-cipher', slug)
                        self.assertEqual('http://127.0.0.1:8766', parsed.scheme + '://' + parsed.netloc)
                    else:
                        self.assertEqual('source', entry['kind'])
                        self.assertEqual('https://github.com/lilyofashwood/' + slug, entry['path'])
        self.assertEqual({'chatlog-printer':2,'melody-cipher':12,'moon-tears':4,
                          'ouroboros-cipher':4,'hexmoji':4,'zalgo-cipher':3,'font-garden':8,
                          'diacritic-bloom':8,'uniception':17,'kagami-no-migaka':3,
                          'ghost-hex':3,'twitterpainted':3,'messageloggerfix':1}, counts)
        self.assertIn("localPreview||entry.kind!=='local'", html)
        self.assertIn("details?.matches('.variants')", html)
        self.assertIn("doors.dataset.searchOpened='true'", html)

if __name__ == '__main__':
    unittest.main()
