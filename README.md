ShjowMe

Vanity pages and Discord invite links. Profiles live at /usr/name, invites at /inv/name.

Run it locally

    pip install -r requirements.txt
    python app.py

Open http://127.0.0.1:5000. By default the first account you register becomes the owner (badge plus the /admin page). Owners can make other people staff. Staff can ban users and delete invites.

Deploy on Railway

1. Push this folder to a GitHub repo and create a Railway project from it. The Procfile is picked up automatically.
2. Add a Volume to the service and mount it at /data. Without one, the database and uploads are wiped on every deploy.
3. Set these variables on the service:
   DATA_DIR=/data
   OWNER_USERNAME=the username you will register as the owner
   SECRET_KEY=any long random string
4. Generate a domain under Settings, Networking, then register your owner account first.

Keep it to one replica, since the data lives in SQLite on the volume. Back the volume up now and then.

Notes

Music length is checked with mutagen, so keep it installed. Invite status is checked against Discord's public API and cached for ten minutes. Uploaded files are served from /u/. Analytics cover the last 30 days.
