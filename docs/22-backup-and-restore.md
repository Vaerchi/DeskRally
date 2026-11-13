# Backup and restore

This is the detailed operating runbook for the checked-in encrypted PostgreSQL backup script and
for recovering the surrounding deployment state. A database restore drill was recorded on
2026-08-30; that historical result does not validate another installation or a recording restore.
Use section 5 to test your own recovery set.

Start with the [Docker installation guide](guides/server-deployment.md) or
[native installation guide](guides/native-server.md). The automatic script below is for Docker;
native deployments need an equivalent database-owner backup job and their service configuration files.

---

## 0. The database is not the whole state

Read this before anything else, because a restore that follows only §3 produces a **working control
plane that every enrolled agent rejects.**

`pg_dump` captures tenants, users, credentials, machines, groups, sessions and the audit chain. It
does **not** capture `deploy/.env`, and `.env` holds:

* **`GRANT_ISSUER_SEED`** — agents pin the public key derived from it. Restore the database with a
  different seed and every enrolled agent refuses every backstage grant, permanently, with no error
  the operator will connect to the restore. **This is the single most important value on the host.**
* **`DIRECTIVE_SIGNING_SEED`** — a separate stable fleet-directive key; agents pin its public key too.
* **`TOTP_ENCRYPTION_KEY`** — required to decrypt the stored authenticator secrets it encrypted.
* **`RECORDING_MASTER_KEY`, `RECORDING_MASTER_KEY_ID` and `RECORDING_MASTER_KEY_PREVIOUS`** — only once central recording is
  switched on (docs/63; off and empty by default). **MUST be backed up, and BEFORE the first recording is written**: every
  stored recording is encrypted under a per-recording key that this one wraps, so losing it makes every recording it wrapped
  permanently unreadable, with no recovery from the database or the volume. During a rotation `_PREVIOUS` is part of the set
  too (it is the READ path for every file still wrapped by an older key), and an old key stays in the set until no stored file
  or backup still depends on it. `CP_PUBLIC_ORIGIN` (the upload-signature audience) belongs here as well: it is ordinary
  configuration, but a restore with a different value makes every agent's uploads fail the signature check.
* `APP_DB_PASSWORD`, `POSTGRES_PASSWORD` — the restored database will not be reachable without them.
* `CP_DEVICE_IDENTITY_TOKEN`, `SIGNALING_TICKET_PUBKEY` — signaling refuses to start without them.

**The backup set includes the dump and all persistent configuration and keys.** They must be kept together and
kept somewhere the host's disk failing does not also destroy. `deploy/.env` changes rarely; copy it
once, and again whenever it changes.

For native installs, include the package's config/*.env files instead of assuming deploy/.env exists.
Also preserve published agent artifacts and proxy certificate storage. Keep encrypted off-host copies.

The dump holds the recording **metadata** (the `session_recording*` tables and the per-tenant recording policy) and never the
recording **files**. Where those files live depends on whether central recording storage is on (docs/63; default OFF):

* **Off (the default):** a recording exists only on the guest machine (`C:\rmt-agent\recordings`, 72 h) and nothing on the
  server holds it, so there is nothing here to back up.
* **On:** a finished recording is uploaded by the agent to the server's recordings volume (Docker: the `recordings` named
  volume, mounted at `/var/lib/deskrally/recordings`; native: `RECORDING_DIR`). Every file there is encrypted (docs/63 C5); the
  local copy is deleted only after the server confirms it. **That volume is OUTSIDE this backup contract in v1** (section 4 states
  the contract and what it means). See also [recording storage and rotation](guides/native-server.md#recording-storage-and-key-rotation).

---

## 1. What runs

`deploy/backup-db.sh`, daily, via `deploy/bridge-backup.timer`. It writes
`~/bridge-backups/bridge-<db>-<STAMP>.sql.gz.age` (age-encrypted, gzip'd SQL). The one-time key setup
in §7 is REQUIRED before the first run. Install:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/bridge-backup.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now bridge-backup.timer
loginctl enable-linger "$USER"
```

**`enable-linger` is not optional.** Without it a user unit runs only while that user has a login
session, so the timer stops firing the moment you close SSH — silently, which is the worst way for a
backup to stop.

Check it:

```bash
systemctl --user list-timers bridge-backup.timer
systemctl --user status bridge-backup.service     # last run's exit status
ls -lh ~/bridge-backups/
```

## 2. What the script refuses to do

Each of these exists because the failure it prevents produces a file that *looks* like a backup:

* **Dumps as the OWNER, never `rmt_app`.** `rmt_app` is `NOSUPERUSER` with row-level security
  applied, so a dump taken as it would be silently partial — complete-looking, containing only
  whatever tenant happened to be pinned.
* **Writes `.partial`, renames on success.** An interrupted run (reboot mid-dump, full disk) cannot
  leave a truncated file sitting in the directory looking finished.
* **Refuses a dump under 4 KB** and **checks the output is a real age stream** before the rename (gzip
  integrity cannot be checked on the box, which holds no decryption key; the restore drill, §5, is the
  integrity check). `pg_dump` can
  emit a valid-but-empty script when pointed at the wrong database, and exit 0 doing it.
* **Refuses to run without an encryption recipient.** Dumps are piped through `age` as they are
  written (a plaintext copy never touches the disk), so only encrypted files exist locally and only
  encrypted files can be copied off-box. No recipient configured = the script exits 1 with the
  one-line fix; there is no plaintext fallback. See §7.
* **Retention by COUNT, not age.** Age-based pruning deletes everything once the job has been
  failing for longer than the window — exactly when the old copies are all you have.

---

## 3. Restore

### Into a scratch database (do this first, always)

This is also the drill in §5. It touches nothing live.

```bash
cd <install>/deploy   # the directory you installed into, e.g. /opt/deskrally/deskrally-server-<version>
set -a; . ./.env; set +a

docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -T \
  -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
  psql -U "${POSTGRES_USER:-rmt}" -d postgres -c 'CREATE DATABASE restore_check'

# Decrypt with the operator's PRIVATE key (kept OFF the server, §7); the plaintext is never written to disk.
age -d -i ~/age-backup-key.txt ~/bridge-backups/bridge-rmt-<STAMP>.sql.gz.age | gunzip -c \
  | docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -T \
      -e PGPASSWORD="$POSTGRES_PASSWORD" postgres \
      psql -U "${POSTGRES_USER:-rmt}" -d restore_check
```

Then compare the restored copy against the LIVE one. **"The dump has rows" is a far weaker claim
than "these two values are identical"**, and only the second says the restore is usable:

```sql
-- 1. THE CREDENTIAL. If this differs the restore cannot be logged into. Note the digest lives on
--    user_credential — app_user has NO password column at all, which is easy to guess wrong.
SELECT t.slug, u.email, c.password_hash
  FROM user_credential c JOIN app_user u ON u.id = c.user_id JOIN tenant t ON t.id = u.tenant_id;

-- 2. THE AUDIT CHAIN HEAD. The chain's whole value is being tamper-evident, so "the rows are there"
--    proves nothing; the HEAD HASH proves the links survived intact.
SELECT tenant_id, count(*) AS rows FROM audit_event GROUP BY tenant_id ORDER BY tenant_id;
SELECT DISTINCT ON (tenant_id) tenant_id, seq, hash
  FROM audit_event WHERE seq IS NOT NULL
  ORDER BY tenant_id, seq DESC;

-- 3. Shape, as a cheap cross-check.
SELECT (SELECT count(*) FROM tenant)     AS tenants,
       (SELECT count(*) FROM app_user)   AS users,
       (SELECT count(*) FROM membership) AS memberships;
```

Run each against BOTH databases and diff. Identical is the pass condition; anything else is a failed
restore however healthy the load looked.

Drop it when done: `DROP DATABASE restore_check`.

**Restoring into a NEW cluster: create `rmt_definer` first (docs/67).** `backup-db.sh` dumps one database, no
globals, so the dump's `ALTER FUNCTION ... OWNER TO rmt_definer` and `GRANT ... TO rmt_definer` lines need the
role to exist (as with `rmt_app`). If it is missing those statements fail, the load carries on, and the definer
functions stay owned by the restoring superuser: the exposure 0076 removed. Restoring an already-migrated dump does
NOT rerun 0076 (the ledger says it ran), so its attribute pin and its refusal of a dirty pre-existing role do not
protect this path: the checks below are the only ones. Before loading, as the superuser, create the role only when
absent:

```sql
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_definer') THEN
  CREATE ROLE rmt_definer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS; END IF; END $$;
```

If the role ALREADY existed, do not trust it: run the validation block below BEFORE loading, and again after (run it in
the target database; the database-level and cluster-wide parts are the same in any database). Every query must return
zero rows (attributes: exactly one row, all `ok`). Anything else: stop and fix the role by hand (`ALTER ROLE ... NOLOGIN
NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS`, `REVOKE` the memberships and grants listed), because
nothing will clean it for you.

```sql
-- 1. attributes: must be one row with ok = true
SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND rolbypassrls AS ok
  FROM pg_roles WHERE rolname = 'rmt_definer';
-- 2. memberships, either direction
SELECT roleid::regrole, member::regrole FROM pg_auth_members
 WHERE roleid = 'rmt_definer'::regrole OR member = 'rmt_definer'::regrole;
-- 3. owned objects other than routines (shared dependencies: this database and cluster-wide objects)
SELECT classid::regclass, pg_describe_object(classid, objid, objsubid) FROM pg_shdepend
 WHERE refclassid = 'pg_authid'::regclass AND refobjid = 'rmt_definer'::regrole AND deptype = 'o'
   AND classid <> 'pg_proc'::regclass AND dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()));
-- 4. explicit privileges: only USAGE on schema public and the table grants of migration 0076 may appear
SELECT 'schema ' || n.nspname, a.privilege_type FROM pg_namespace n, aclexplode(n.nspacl) a
 WHERE a.grantee = 'rmt_definer'::regrole AND NOT (n.nspname = 'public' AND a.privilege_type = 'USAGE')
UNION ALL SELECT 'database ' || datname, a.privilege_type FROM pg_database d, aclexplode(d.datacl) a WHERE a.grantee = 'rmt_definer'::regrole
UNION ALL SELECT 'tablespace ' || spcname, a.privilege_type FROM pg_tablespace t, aclexplode(t.spcacl) a WHERE a.grantee = 'rmt_definer'::regrole
UNION ALL SELECT 'routine ' || p.oid::regprocedure, a.privilege_type FROM pg_proc p, aclexplode(p.proacl) a
 WHERE a.grantee = 'rmt_definer'::regrole AND p.proowner <> 'rmt_definer'::regrole
UNION ALL SELECT 'relation ' || c.oid::regclass, a.privilege_type FROM pg_class c, aclexplode(c.relacl) a
 WHERE a.grantee = 'rmt_definer'::regrole AND NOT (c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p'))
UNION ALL SELECT 'column ' || c.relname || '.' || t.attname, a.privilege_type FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid, aclexplode(t.attacl) a
 WHERE a.grantee = 'rmt_definer'::regrole
UNION ALL SELECT 'type ' || t.oid::regtype, a.privilege_type FROM pg_type t, aclexplode(t.typacl) a WHERE a.grantee = 'rmt_definer'::regrole
UNION ALL SELECT 'language ' || lanname, a.privilege_type FROM pg_language l, aclexplode(l.lanacl) a WHERE a.grantee = 'rmt_definer'::regrole
UNION ALL SELECT 'large object ' || l.oid, a.privilege_type FROM pg_largeobject_metadata l, aclexplode(l.lomacl) a WHERE a.grantee = 'rmt_definer'::regrole
UNION ALL SELECT 'foreign data wrapper ' || fdwname, a.privilege_type FROM pg_foreign_data_wrapper w, aclexplode(w.fdwacl) a WHERE a.grantee = 'rmt_definer'::regrole
UNION ALL SELECT 'foreign server ' || srvname, a.privilege_type FROM pg_foreign_server s, aclexplode(s.srvacl) a WHERE a.grantee = 'rmt_definer'::regrole
UNION ALL SELECT 'default privileges ' || d.oid, '' FROM pg_default_acl d
 WHERE d.defaclrole = 'rmt_definer'::regrole OR EXISTS (SELECT 1 FROM aclexplode(d.defaclacl) a WHERE a.grantee = 'rmt_definer'::regrole);
-- 4b. PostgreSQL 15+ only (the table does not exist on 14): parameter privileges
SELECT 'parameter ' || parname, a.privilege_type FROM pg_parameter_acl p, aclexplode(p.paracl) a WHERE a.grantee = 'rmt_definer'::regrole;
-- 4c. table privileges that 0076 did not grant: a grant option, or a grantor other than the table's owner (another
--     role's grant survives the owner's REVOKE ALL); must be zero rows
SELECT c.relname, a.privilege_type, a.grantor::regrole, a.is_grantable FROM pg_class c, aclexplode(c.relacl) a
 WHERE a.grantee = 'rmt_definer'::regrole AND c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
   AND (a.is_grantable OR a.grantor <> c.relowner);
-- 4d. EFFECTIVE table/sequence privileges (PUBLIC reaches every role): a table privilege it has without its own
--     owner-granted entry, or any sequence privilege; must be zero rows
SELECT c.relname, p.priv FROM pg_class c
 CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) p(priv)
 WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r','p')
   AND has_table_privilege('rmt_definer', c.oid, p.priv)
   AND NOT EXISTS (SELECT 1 FROM aclexplode(c.relacl) a
                   WHERE a.grantee = 'rmt_definer'::regrole AND a.grantor = c.relowner AND a.privilege_type = p.priv)
UNION ALL
SELECT c.relname, p.priv FROM pg_class c CROSS JOIN (VALUES ('USAGE'),('SELECT'),('UPDATE')) p(priv)
 WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S' AND has_sequence_privilege('rmt_definer', c.oid, p.priv);
-- 4e. PUBLIC hygiene: any PUBLIC privilege beyond PostgreSQL's defaults (function EXECUTE, type/language USAGE,
--     database CONNECT/TEMPORARY, USAGE on schema public) reaches every role; must be zero rows
--     (PostgreSQL 15+ also: SELECT parname, privilege_type FROM pg_parameter_acl p, aclexplode(p.paracl) a WHERE a.grantee = 0;)
SELECT 'relation ' || n.nspname || '.' || c.relname || ' ' || a.privilege_type
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a
 WHERE a.grantee = 0 AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
UNION ALL SELECT 'column ' || n.nspname || '.' || c.relname || '.' || at.attname || ' ' || a.privilege_type
  FROM pg_attribute at JOIN pg_class c ON c.oid = at.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(at.attacl) a
 WHERE a.grantee = 0 AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
UNION ALL SELECT 'schema ' || n.nspname || ' ' || a.privilege_type FROM pg_namespace n, aclexplode(n.nspacl) a
 WHERE a.grantee = 0 AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
   AND NOT (n.nspname = 'public' AND a.privilege_type = 'USAGE')
UNION ALL SELECT 'database ' || d.datname || ' ' || a.privilege_type FROM pg_database d, aclexplode(d.datacl) a
 WHERE a.grantee = 0 AND a.privilege_type NOT IN ('CONNECT', 'TEMPORARY')   -- every database of the cluster
UNION ALL SELECT 'large object ' || l.oid || ' ' || a.privilege_type FROM pg_largeobject_metadata l, aclexplode(l.lomacl) a WHERE a.grantee = 0
UNION ALL SELECT 'foreign data wrapper ' || w.fdwname || ' ' || a.privilege_type FROM pg_foreign_data_wrapper w, aclexplode(w.fdwacl) a WHERE a.grantee = 0
UNION ALL SELECT 'foreign server ' || s.srvname || ' ' || a.privilege_type FROM pg_foreign_server s, aclexplode(s.srvacl) a WHERE a.grantee = 0
UNION ALL SELECT 'tablespace ' || t.spcname || ' ' || a.privilege_type FROM pg_tablespace t, aclexplode(t.spcacl) a WHERE a.grantee = 0;
-- 5. effective CREATE: must be zero rows / false (a direct grant or PUBLIC can give it)
SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'
   AND has_schema_privilege('rmt_definer', oid, 'CREATE');
SELECT has_database_privilege('rmt_definer', current_database(), 'CREATE');   -- must be false
```

The owner-granted table privileges themselves (query 4c lists only grant options and other grantors) are checked by eye or by diff against the
`GRANT ... TO rmt_definer` lines of `migrations/0076_definer_owner.sql`; a dump taken from a migrated database carries
exactly those lines, so a restored database matches by construction and an existing role is the case to inspect.

After loading, this must return 0 (a restore into the SAME cluster already has the role), AND the validation block above
must still pass, AND ownership of every definer routine is verified, not assumed:

```sql
SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
 WHERE p.prosecdef AND p.pronamespace = 'public'::regnamespace AND r.rolname <> 'rmt_definer';
```

### For real

```bash
dc down                       # NOT -v. -v destroys the volume you are restoring into.
dc up -d postgres
# ... psql the dump into the live database as above, using $POSTGRES_DB ...
dc up -d
```

The dump is taken with `--clean --if-exists`, so it drops and recreates its own objects. Restoring
over a live database is destructive by design — that is what makes §5 mandatory.

---

## 4. What is still not covered

* **Off-host copies.** Everything above writes to the same disk as the database. A disk failure
  takes both. Copy `~/bridge-backups/` and `deploy/.env` somewhere else — that is the step that
  turns this from "an undo button" into a backup.
* **Encryption at rest** is done for the dump (age, §7). `deploy/.env` (it holds `GRANT_ISSUER_SEED`)
  is not covered by the script: encrypt it the same way before copying it off-box
  (`age -r <public key> -o env.age deploy/.env`).
* **Point-in-time recovery.** Daily snapshots only. WAL archiving would be needed for finer
  granularity, and is a much larger undertaking.
* **A tested restore.** See below.
* **Central recording (docs/63), only if switched on.** The contract for v1, written so the deployment owner can accept or
  counter it (it is a PROPOSAL until the owner has explicitly accepted it; see "Acceptance" below):
  * **The master key is in the must-back-up set** (section 0), together with `RECORDING_MASTER_KEY_PREVIOUS` during and after a
    rotation. `deploy/backup-db.sh` does not copy `deploy/.env`; copy it as section 0 already says.
  * **The recordings volume is NOT backed up** by the script, by the timer, or by anything else this repo ships. The tenant's
    retention setting (30/90/... days) is a **deletion policy, not a durability guarantee**: it says when a recording will
    be removed, never that it will still exist until then. Losing the volume (a disk failure, `docker compose down -v`,
    `docker volume rm`/`prune`, a rebuilt host) loses the recordings it held even when the database backup is perfect, and
    the console keeps listing them until they expire (below). An operator who needs more may snapshot the volume with
    their own tooling (stop uploads and cleanup first: a copy taken mid-upload or mid-sweep is not a consistent set); that
    is an addition to, not part of, this contract.
  * **The volume shares the root filesystem (the same LV) with Postgres** on the reference host. A recordings burst that fills the
    disk would stop the database too, so the server refuses new recording uploads while free space on that filesystem is below a
    configurable floor (`RECORDING_DISK_FLOOR_MIB`, default 5 GiB, docs/20 section 15.1) and logs an `ALERT` line the moment one is
    refused. Treat that line as a page.
  * **Acceptance.** Do not enable central recording for real tenants until the deployment owner has said, in writing, that
    "recordings are not covered by the backup, retention is a deletion policy, the master key is" is acceptable (docs/63 C11).
    If it is not, the alternative to decide on is a volume snapshot/replication job; none exists yet.
* **Reconciling a restored database with the volume (what the code does today, and what it does not).** There are three
  restores and the control plane treats them differently:
  * **Rows with no blob** (database restored, volume empty or older). Marked **`lost`** by the reconciliation pass below, and
    only by it: `lost` is never set during normal operation. A `lost` row is listed in the console as "Lost: the file is
    missing after a restore", answers `410` (`error: "lost"`) to playlist, stream and download before storage is touched, is
    never queued for playback, and still ages out by retention like any other row (the row goes `expired` then `deleted`;
    there is nothing on disk to unlink, which is a successful no-op). It keeps the state it was lost from (`lost_from`) and
    when (`lost_at`), and keeps them as history after a restore or an expiry, and each loss is a `recording.lost` audit event. Only a row that promises evidence on the volume
    (`evidence_complete`, `playback_ready`, `playback_failed`) can become lost.
  * **Blobs with no row** (volume newer than the database, or a database restored to an earlier point). The orphan pass (every
    5 minutes, on the reaper tick) **never deletes**: it moves a UUID-named recording directory that no live row claims into
    `<volume>/.quarantine/<unix>-<name>/` with a `MANIFEST.json` (origin path, reason, time), and purges ONLY entries it
    created itself, 14 days after quarantine. A directory younger than 1 hour is never moved (a create or promote may still be racing it). It holds (and logs an `ALERT`) when the database read failed, when most
    directories look orphaned, or beyond 50 moves per pass. Anything not named like a recording is skipped and reported, never
    touched.
  * **`RECORDING_RECONCILE_MODE=1`** (also `true`, `yes`, `on`; the control plane logs `reconcile_mode=true` at startup)
    is the restore-drill switch. It turns the orphan pass off completely, the quarantine purge with it (in that window the
    control plane will not move or remove any unclaimed blob, but retention for rows it does know still deletes expired
    files, and uploads still work), **and it turns on the `lost` pass**. Nothing outside this mode ever marks a row lost.
  * **The restore drill, exactly.**
    1. Restore the database, and restore (or leave empty) the recordings volume. Mount the volume you mean to use at
       `/var/lib/deskrally/recordings` (the `recordings` named volume) BEFORE the next step.
    2. Set `RECORDING_RECONCILE_MODE=1` in `.env` and recreate the control plane: `dc up -d --force-recreate controlplane`.
    3. Read the summary line: `dc logs controlplane | grep 'recording reconcile: lost pass' | tail -n 1`. It prints
       `checked=N present=N marked_lost=N restored=N playback_demoted=N still_lost=N unreadable=N audit_failed=N held="..."`.
       It is logged at startup and again on every 5-minute sweep tick while the mode is on, so the numbers settle as you
       restore files (read the newest line; `checked` counts only rows not already lost, so it can shrink between passes).
    4. **If `held` is not empty, NOTHING was changed** (no row marked, none restored) and an `ALERT` line says why. The pass holds
       when (a) the volume root cannot be read (never overridden: fix the mount), or it goes away while the pass is marking (the root is re-checked before every mark; also never overridden), (b) at least 10 recordings are checked and
       MORE THAN HALF are missing their files, or (c) the volume holds no recording directory at all while rows claim
       files, or (d) fewer than 10 recordings are checked and every one is missing. (b), (c) and (d) look exactly like an unmounted or wrong volume, so check `docker volume ls`, the mount and
       `ls /var/lib/deskrally/recordings` first. If the volume IS the right one and the files really are gone, set
       `RECORDING_RECONCILE_ACCEPT_MISSING=1` as well, recreate, and read the summary again; that statement is yours to make,
       the code cannot verify it.
    5. Rows whose files cannot be inspected at all (permissions, a link, a foreign filesystem, or a segment file that exists but is empty) are counted as `unreadable` and
       left alone, never marked lost.
    6. A `lost` row whose files reappear (you restore a volume snapshot while the mode is still on) is **restored** to the state
       it was lost from on the next tick (`restored=N`; a `playback_ready` row whose playback copy did not come back returns
       as `evidence_complete`, so the muxer rebuilds it), with a `recording.restored` audit event. A `playback_ready` row whose
       playback copy is missing but whose evidence is present becomes `playback_failed` (`io_error`), still downloadable as
       evidence (`playback_demoted=N`).
    7. When the summary shows what you expect, **unset `RECORDING_RECONCILE_MODE` (and `_ACCEPT_MISSING`) and recreate the
       control plane again.** From then on the orphan pass is back on and nothing marks or restores rows. Rows that were
       marked `lost` stay lost until retention removes them (restoring files later needs the mode on again).
  * **Blobs with no row** are not touched in reconcile mode; once it is off, the orphan pass quarantines them as described above. If
    a blob was quarantined by mistake, move its directory back out of `.quarantine/` (the manifest names the original path)
    while the control plane is stopped or in reconcile mode.
  * What is **not** provided by code: no check that a restored key matches the `key_id` of the rows, and no automated copy of the
    volume. Record the outcome of your own drill (section 5).

---

## 5. It is not a backup until a restore has been tested

**Do this once now, and once a quarter after.** An untested backup is a belief.

1. Quiesce writes or take the expected comparison snapshot first; comparing a new backup with a
   database that has continued changing is not an equality test. Restore the dump into `restore_check` (§3).
2. Confirm the counts and the credential digest.
3. **Best evidence:** point a scratch control plane at `restore_check` and log in with the real
   credentials. That proves the argon2id digest and the credential epoch both survived the round
   trip — the two things whose failure would leave you holding a restored database you cannot enter.

4. If central recording is enabled (docs/63): start the scratch control plane with the restored `.env` key set
   (`RECORDING_MASTER_KEY`, `_ID`, and `_PREVIOUS` if you rotated) and `RECORDING_RECONCILE_MODE=1`, against an EMPTY
   scratch volume (the production volume is not in the backup, so this is the real disaster case). Expect: the summary line
   `recording reconcile: lost pass` (section 4) and, because every file is missing, a HOLD (`held="held: the volume holds no
   recordings at all..."`) with nothing changed. Then set `RECORDING_RECONCILE_ACCEPT_MISSING=1` and recreate: every row
   promising a file is now `lost`, the console shows them as Lost and playback and download answer 410, no file touched. Then,
   if you keep your own volume snapshots, restore one and confirm the rows come back (`restored=N`) and a recording from before
   the key rotation and one after both play. Record what you saw; the point is that the operator has seen the "rows with no
   blob" state BEFORE the day it matters.
5. Verify a new authenticated remote session, agent presence and service restart behavior against
   the isolated installation. Record the release, snapshot time, key IDs and results privately.

## 6. There are two backups, on purpose

* **On-host** (this script + timer): local, always runs, fast to restore from. Survives *the database
  being wrong*.
* **Off-host** (a pull to the operator's OneDrive, built separately): survives *the host being gone*.
  It fetches what this script produces rather than dumping again, so there is exactly one `pg_dump`
  and one thing to reason about.

Different failure domains — a disk dying versus a house fire — which is why neither replaces the
other.

## 7. Encryption and key management

Backups are encrypted with [age](https://age-encryption.org) to one or more **public** keys
(recipients). The server holds only the public key, so a stolen disk, a stolen OneDrive copy or a
leaked `~/bridge-backups` reveals nothing. Decryption needs the matching **private** key.

**One-time setup (on the operator's workstation, NOT the server):**

```bash
age-keygen -o deskrally-backup-key.txt      # the "Public key: age1..." line is what the server needs
# Store deskrally-backup-key.txt in the password manager (plus a second offline copy), then delete the local file.
```

**On the server** (needs the `age` package: `apt install age`), set the PUBLIC key in `deploy/.env`
(the script sources it) or in the systemd unit:

```
BRIDGE_BACKUP_AGE_RECIPIENT=age1xxxxxxxx...            # one or several, comma-separated
# or: BRIDGE_BACKUP_AGE_RECIPIENTS_FILE=/path/recipients.txt   (one per line; may hold ssh public keys)
```

Prefer two recipients (the operator plus a break-glass key held by someone else) so losing one key is
not losing the backups. Run `deploy/backup-db.sh`, then decrypt the newest file on the workstation
(`age -d -i key.txt file.sql.gz.age | gunzip -c | head`) BEFORE trusting it.

**Key management rules**

* **The private key must live OFF the server** (password manager, offline copy). If it is on the box,
  encryption protects nothing; the script rejects an `AGE-SECRET-KEY-...` value given as a recipient.
* **Losing every private key means losing every backup.** There is no recovery and no backdoor.
  Test a decrypt after any key change and record the date in the §5 table.
* Rotating: add the new public key as a recipient (new backups use it) and keep the old private key
  for as long as old backups you may need exist. Removing a recipient does not re-encrypt old files.

**Migrating from plaintext backups**

1. Set the recipient and run `deploy/backup-db.sh` once; confirm a `bridge-*.sql.gz.age` appears.
2. The script warns on every run about legacy `bridge-*.sql.gz` files and does NOT prune them. After
   a verified encrypted copy exists, delete them (`shred -u ~/bridge-backups/bridge-*.sql.gz`, best
   effort on journaling/SSD filesystems) and remove any plaintext copies already off-box.
3. **Update the off-box (OneDrive) copier to pick up `bridge-*.sql.gz.age`.** The new name does not
   match the old `*.sql.gz` pattern, so a copier that globs that will silently copy nothing new.
   Local retention prunes by name on the `.age` files.
