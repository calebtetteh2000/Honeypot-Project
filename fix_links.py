import glob

extra = [
    ('href="wp-pages.html"', 'href="/wp-dashboard"'),
    ('href="wp-comments.html"', 'href="/wp-dashboard"'),
    ("href='wp-pages.html'", "href='/wp-dashboard'"),
    ("href='wp-comments.html'", "href='/wp-dashboard'"),
    ('href="wp-posts.html"', 'href="/wp-posts"'),
    ('href="wp-media.html"', 'href="/wp-media"'),
    ('href="wp-users.html"', 'href="/wp-users"'),
    ('href="wp-plugins.html"', 'href="/wp-plugins"'),
    ('href="wp-settings.html"', 'href="/wp-settings"'),
    ('href="wp-security.html"', 'href="/wp-security"'),
    ('href="wp-appearance.html"', 'href="/wp-appearance"'),
    ('href="wp-dashboard.html"', 'href="/wp-dashboard"'),
    ("href='wp-posts.html'", "href='/wp-posts'"),
    ("href='wp-media.html'", "href='/wp-media'"),
    ("href='wp-users.html'", "href='/wp-users'"),
    ("href='wp-plugins.html'", "href='/wp-plugins'"),
    ("href='wp-settings.html'", "href='/wp-settings'"),
    ("href='wp-security.html'", "href='/wp-security'"),
    ("href='wp-appearance.html'", "href='/wp-appearance'"),
    ("href='wp-dashboard.html'", "href='/wp-dashboard'"),
]

for f in glob.glob('templates/*.html'):
    with open(f, encoding='utf-8', errors='ignore') as fp:
        content = fp.read()
    for old, new in extra:
        content = content.replace(old, new)
    with open(f, 'w', encoding='utf-8') as fp:
        fp.write(content)
    print('Fixed', f)

print('Done!')