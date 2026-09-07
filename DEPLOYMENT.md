# DL Tracker - deployment notes

Prepared for IT by Ali Demir (HR). Everything needed to move the application
from a workstation onto a server and publish it under an internal domain name.

---

## 1. What the application is

An internal web application used by HR to track driver's licence applications
and renewals for employees across the group's sites. It replaces a set of
spreadsheets. It is used by fewer than ten people, plus one phone used at the
driving licence office.

- Back end: Python, FastAPI, served by uvicorn - a single file, `main.py`.
- Front end: one static file, `web/index.html`. No build step, no npm.
- Database: PostgreSQL.
- Traffic is light: short JSON requests, occasional Excel report downloads.
- No internet access is required, inbound or outbound.

---

## 2. What is in this package

| File | What it is |
|---|---|
| `main.py` | The entire application - HTTP API plus the command line tools below |
| `schema.sql` | Database schema, applied once by `initdb`. Also seeds the company list and the fee table |
| `web/index.html` | The complete front end, single file |
| `dl-config.example.txt` | Settings template - rename to `dl-config.txt` and fill in |
| `requirements.txt` | The three Python packages needed |

There are no other files, no assets folder and no bundled binaries.

---

## 3. Requirements

- Python 3.10 or newer (developed and running on 3.12)
- PostgreSQL 14 or newer (currently PostgreSQL 18 on the workstation)
- Three Python packages: `fastapi`, `uvicorn`, `psycopg2-binary`
- One TCP port. 8000 by default, configurable.

The application is platform neutral - it runs on Windows Server or Linux with
no code changes. Linux is preferred if there is a choice, purely because
running it as a service is simpler there.

---

## 4. Installation

    # 1. put the folder on the server, e.g. /opt/dltracker
    python -m pip install -r requirements.txt

    # 2. create the database role and the settings file
    #    (rename dl-config.example.txt to dl-config.txt and fill it in)

    # 3. verify PostgreSQL is reachable with those settings
    python main.py check

    # 4. create the database and apply the schema
    python main.py initdb

    # 5. create the first account (it will prompt for a password)
    python main.py adduser ali.demir@company.com "Ali Demir" Admin

    # 6. start it
    python main.py serve

`initdb` connects to the `postgres` maintenance database to issue
`CREATE DATABASE`, so the role in `dl-config.txt` needs `CREATEDB` for that one
step. Afterwards it only needs ownership of the `dltracker` database. If you
would rather create the database yourself, do so and `initdb` will detect it
and apply the schema only.

### Command line reference

| Command | What it does |
|---|---|
| `python main.py check` | Reports whether PostgreSQL is reachable and prints the build |
| `python main.py initdb` | Creates the database if missing, applies `schema.sql` |
| `python main.py adduser <email> "<name>" <Admin\|Viewer>` | Creates an account, prompts twice for the password |
| `python main.py serve` | Starts the HTTP server |
| `python main.py password` | Writes the database settings into `dl-config.txt` interactively |
| `python main.py reset` | Deletes all licence records, keeps accounts and reference data. Asks for typed confirmation |

---

## 5. Configuration

Settings are read from `dl-config.txt` next to `main.py`. Every key can also be
supplied as an environment variable of the same name, which takes priority - use
that if the database password should not sit in a file.

    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS
    HOST      0.0.0.0 by default. Set to 127.0.0.1 if only a local reverse
              proxy should reach the application directly.
    PORT      8000 by default.

---

## 6. Running it as a service

### Linux (systemd)

    [Unit]
    Description=DL Tracker
    After=network.target postgresql.service

    [Service]
    Type=simple
    User=dltracker
    WorkingDirectory=/opt/dltracker
    ExecStart=/usr/bin/python3 /opt/dltracker/main.py serve
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target

### Windows Server

Any service wrapper works - NSSM, or a Scheduled Task set to "At startup" with
"Run whether user is logged on or not". The command is
`python.exe main.py serve` with the working directory set to the install folder.

---

## 7. Publishing it under the domain name

The application serves the user interface at `/` and its API under `/api`.
Every request the browser makes is relative, so it works unchanged behind a
reverse proxy mapped to the root of a host name, for example
`https://dltracker.company.local/`.

Points worth knowing before you configure the proxy:

- **Authentication uses an `Authorization: Bearer <token>` header, not cookies.**
  There is nothing to set for cookie domains, SameSite or session affinity.
  Please make sure the proxy forwards the `Authorization` header.
- **Sub-paths are supported.** Dynamic URL resolution in the frontend and
  the `ROOT_PATH` setting allow serving under paths like `/dl` (e.g. `https://inciatolyesi.com/dl`).
- **HTTPS**: the application speaks plain HTTP only. Terminating TLS at the
  proxy is fine and is the preferred arrangement.
- **No WebSockets and no server-sent events.** A standard HTTP proxy config is
  enough.
- **Timeouts**: the longest request is an Excel report download, a few seconds
  on current data volumes. A 60 second read timeout is generous.
- **Upload size**: photographs taken at the licence office are posted as
  base64 JSON. Please allow a request body of at least 10 MB.

### The phone used at the licence office

Staff at the driving licence office work where the network is weak. The web app
keeps its work in the browser's IndexedDB and syncs when it is back on the
company network, so it must be able to reach the same host name from the site
Wi-Fi. It polls `/api/ping` to find out whether it is back online.

---

## 8. Data, backup and retention

- All application data lives in the single PostgreSQL database, `dltracker`.
  Nothing else is written to disk except `dl-config.txt` and the log output.
- Licence photographs are stored **in the database**, in `application_photo`.
  A database backup is therefore a complete backup - there is no separate file
  store to remember.
- Suggested backup: `pg_dump -F c dltracker` nightly, retained per the standard
  policy for HR systems.
- The database holds employee personal data - names, registration numbers,
  licence details and photographs. It should be treated at the same
  confidentiality level as the HR system it draws from.

---

## 9. Accounts and security notes

- Two roles: **Admin** (full access) and **Viewer** (read only). Accounts are
  created from the command line with `adduser`.
- Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes from the Python
  standard library. No plaintext passwords are stored anywhere.
- Sessions are opaque random tokens; only their SHA-256 hash is kept in the
  `app_session` table. They expire after 30 days.
- The application is designed for the internal network only and should not be
  published to the internet.

---

## 10. Open questions for IT

1. Which host name will be issued, and will it be served over HTTP or HTTPS?
2. Windows Server or Linux? Both are fine - it changes only the service setup.
3. Will PostgreSQL run on the same server, or on an existing database server?
   If it is an existing one, a dedicated role and database are all that is
   needed.
4. Will the application sit behind a reverse proxy, and at the root of the host
   name or under a sub-path? A sub-path needs a small change on our side.
5. Who should own the backup schedule for the `dltracker` database?

---

Contact: Ali Demir, HR - for anything about the application itself.
