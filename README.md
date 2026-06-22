# Sig Rotator

A modernized, self-contained version of the old Perl/MySQL image rotator.
It stores image URLs and redirects each rotator request to one randomly
selected URL.

## Run it on Windows

1. Install Python 3.10 or newer if it is not already installed.
2. Double-click `start.bat`.
3. Open <http://127.0.0.1:8080>.
4. Create an account, add direct image URLs, and save.

No packages or database server are required. The app creates
`sig-rotator.db` beside `app.py` automatically.

You can also start it from a terminal:

```powershell
py -3 app.py
```

## Rotator URLs

For an account named `example`, both forms work:

```text
http://127.0.0.1:8080/r/example
http://127.0.0.1:8080/example.gif
```

These are redirects, not generated GIF files. Some websites refuse image
redirects or block images hosted on a private/local address.

## Hosting it publicly

The default address is intentionally local-only. Set environment variables to
change it:

```powershell
$env:SIG_ROTATOR_HOST = "0.0.0.0"
$env:SIG_ROTATOR_PORT = "8080"
py -3 app.py
```

For a public deployment, put it behind an HTTPS reverse proxy and keep the
SQLite database backed up. Set `SIG_ROTATOR_DB` to move the database elsewhere.

## Improvements over the original

- No Perl CGI or MySQL setup
- Parameterized database queries
- Salted PBKDF2 password hashes
- Separate registration and login
- CSRF protection for URL changes
- URL validation and output escaping
- Private account management
- Compatibility route ending in `.gif`

The original `everything.pl` page was intentionally omitted because it exposed
every user's account and images.
