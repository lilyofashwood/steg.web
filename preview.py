#!/usr/bin/env python3
"""A loopback-only, exact-allowlist review shelf. Never a directory server."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import mimetypes
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent
REPOS = ROOT.parent
# Literal app directories and literal public-demo files only. No recursive discovery.
APPS = {
    'chatlog-printer': ('chatlog-printer', ('index.html', 'demo.css', 'demo.js', 'store.js', 'render.js', 'archive.html', 'archive.css', 'archive.js', 'transcript.html', 'transcript.css', 'transcript.js', 'icons/icon-48.png', 'presentation.js', 'presentation.css')),
    'melody-cipher': ('melody-cipher', ('gallery.html', 'index.html', 'studio.css', 'examples/comparison/melody_baseline.wav', 'examples/comparison/melody_bloom.wav', 'examples/comparison/glyphs_baseline.wav', 'examples/comparison/glyphs_bloom.wav', 'presentation.js', 'presentation.css')),
    'moon-tears': ('moon-tears', ('index.html', 'presentation.js', 'presentation.css')),
    'ouroboros-cipher': ('ouroboros-cipher', ('index.html', 'style.css', 'core.js', 'typography.js', 'ui.js')),
    'hexmoji': ('hexmoji', ('index.html', 'style.css', 'core.js', 'ui.js', 'presentation.js', 'presentation.css')),
    'zalgo-cipher': ('zalgo-cipher-main', ('index.html', 'zalgo-cipher.html', 'zalgo-cipher-v2.html', 'zalgo-cipher-v3.html', 'v3.css', 'zalgo-v3.js', 'v3-ui.js', 'font-garden.js', 'register-recipes.js', 'bg_image.png')),
    'font-garden': ('font-garden', ('index.html', 'font-garden.js', 'register-recipes.js', 'gallery.js', 'veil_script_font_garden_v0_2_1.html', 'presentation.js', 'presentation.css', 'seams/index.html', 'seams/workshop.mjs', 'seams/seams.css', 'seams/codec.mjs', 'seams/trail.json', 'seams/vendor/uniception-core.mjs', 'seams/vendor/hexmoji-core.mjs', 'seams/vendor/zalgo-mux3.mjs')),
    'diacritic-bloom': ('diacritic-bloom', ('index.html', 'diacritic-bloom.html', 'presentation.js', 'presentation.css')),
    'uniception': ('steg-web', ('index.html', 'style.css', 'core.js', 'lettering.js', 'app.js', 'variants/snowline-mirrorfall/demo.html', 'variants/snowline-mirrorfall/core.js', 'variants/snowline-mirrorfall/specimen.js', 'variants/snowline-mirrorfall/demo.js', 'variants/snowline-mirrorfall/demo.css', 'variants/nekomata-thread/index.html', 'variants/nekomata-thread/app.js', 'variants/nekomata-thread/specimen.js', 'variants/nekomata-thread/style.css')),
    'kagami-no-migaka': ('kasane-uta', ('index.html', 'style.css', 'core.js', 'lettering.js', 'app.js')),
    'ghost-hex': ('ghost-hex-main', ('index.html', 'style.css', 'app.js', 'image.png')),
    'twitterpainted': ('twitterpainted/docs', ('index.html', 'twitterpainted.css', 'twitterpainted.js', 'steg-core.js')),
    'messageloggerfix': ('messageloggerfix-main', ('index.html',)),
}
DEFAULTS = {'melody-cipher': 'gallery.html', 'zalgo-cipher': 'zalgo-cipher-v3.html'}
ALLOWED = {'/': ROOT / 'index.html', '/index.html': ROOT / 'index.html'}
for slug, (folder, filenames) in APPS.items():
    for name in filenames:
        ALLOWED[f'/apps/{slug}/{name}'] = REPOS / folder / name
    ALLOWED[f'/apps/{slug}/'] = REPOS / folder / DEFAULTS.get(slug, 'index.html')
ALLOWED['/apps/font-garden/seams/'] = REPOS / 'font-garden/seams/index.html'

CSP = "; ".join((
    "default-src 'self'", "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'", "img-src 'self' data: blob:",
    "font-src 'self' data:", "media-src 'self' data: blob:",
    "connect-src 'self'", "worker-src 'self' blob:",
    "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
))

def resolve_public_path(target):
    """Decode once, reject ambiguous paths, then look up an exact route."""
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return None
    try:
        path = unquote(parsed.path, encoding='utf-8', errors='strict')
    except UnicodeError:
        return None
    if any(c in path for c in ('\\', '\x00', '%')) or any(p in ('.', '..') for p in path.split('/')):
        return None
    file = ALLOWED.get(path)
    if file is None:
        return None
    # Refuse even allowlisted paths if a later workspace change substitutes a symlink.
    if any(p.is_symlink() for p in (file, *file.parents)):
        return None
    return file if file.is_file() else None

class ReviewHandler(BaseHTTPRequestHandler):
    server_version = 'AshwoodReview/1.0'

    def log_message(self, *_args):
        # Do not depend on a connected terminal or log private review URLs.
        pass

    def end_headers(self):
        policy = CSP.replace("frame-ancestors 'none'", "frame-ancestors 'self'") if getattr(self, '_bloom_frame', False) else CSP
        self.send_header('Content-Security-Policy', policy)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        super().end_headers()

    def do_GET(self):
        self.serve(head=False)

    def do_HEAD(self):
        self.serve(head=True)

    def serve(self, head):
        self._bloom_frame = False
        port = self.server.server_port
        if self.headers.get_all('Host') not in ([f'127.0.0.1:{port}'], [f'localhost:{port}']):
            self.send_error(403, 'Loopback Host required')
            return
        try:
            file = resolve_public_path(self.path)
        except (ValueError, OSError):
            file = None
        if file is None:
            self.send_error(404, 'Not a review asset; use the private repository for source notes')
            return
        # The current Bloom front door embeds only this preserved workshop.
        # Other assets remain unframeable; no cross-origin embedding is allowed.
        self._bloom_frame = file == REPOS / 'diacritic-bloom' / 'diacritic-bloom.html'
        try:
            data = file.read_bytes()
        except OSError:
            self.send_error(404, 'Review asset unavailable')
            return
        content_type = mimetypes.guess_type(file.name)[0] or 'application/octet-stream'
        if file.suffix in ('.js', '.mjs'):
            content_type = 'text/javascript'
        if content_type.startswith('text/'):
            content_type += '; charset=utf-8'
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if not head:
            self.wfile.write(data)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8779)
    parser.add_argument('--check', action='store_true', help='Check every allowlisted file without starting a server')
    args = parser.parse_args()
    if args.check:
        missing = [route for route in ALLOWED if resolve_public_path(route) is None]
        print(f'{len(APPS)} apps; {len(ALLOWED)} exact routes; {len(missing)} missing or unsafe files.')
        for route in missing:
            print(route)
        return 1 if missing else 0
    if not 1024 <= args.port <= 65535:
        parser.error('--port must be between 1024 and 65535')
    try:
        server = ThreadingHTTPServer(('127.0.0.1', args.port), ReviewHandler)
    except OSError as error:
        parser.exit(1, f'Could not open loopback port {args.port}: {error}\n')
    print(f'steg.web local review: http://127.0.0.1:{server.server_port}/', flush=True)
    print('Exact demo assets only. Source notes, background, archives and Git metadata are not served.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
