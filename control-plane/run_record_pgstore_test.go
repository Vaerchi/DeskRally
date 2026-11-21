package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func startRunTestSession(t *testing.T, f *toolboxFixture, device string) SessionRecord {
	t.Helper()
	var started struct {
		Session SessionRecord `json:"session"`
	}
	body, _ := json.Marshal(map[string]string{"machine_id": device})
	if code := apiJSON(t, f.ownerSrv, "POST", "/sessions", string(body), &started); code != http.StatusCreated {
		t.Fatalf("start %s: %d", device, code)
	}
	return started.Session
}

func TestPgRunRequestsInsertBeforeAudit(t *testing.T) {
	f := newToolboxFixture(t)
	ctx := context.Background()
	installed := startRunTestSession(t, f, "tb-dev")
	_, guestID := seedGroupMachine(t, f.su, f.tenant, "guest")
	guest := startRunTestSession(t, f, "guest")
	mustExec(t, f.su, `UPDATE machine SET ephemeral = true WHERE id = $1`, guestID)
	_, item := tbCreate(t, f.ownerSrv, "personal", "Snapshot", "powershell", "Get-Date")

	execScript(t, f.su, `
		CREATE FUNCTION check_test_run_audit_order() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action IN ('command.run_requested', 'toolbox.run_requested') AND
			   (EXISTS (SELECT 1 FROM run_record WHERE request_id = (NEW.metadata->>'request_id')::uuid)
			    IS DISTINCT FROM
			    (SELECT NOT ephemeral FROM machine WHERE id = (NEW.metadata->>'machine_id')::uuid)) THEN
				RAISE EXCEPTION 'incorrect run row at request audit insert';
			END IF;
			RETURN NEW;
		END
		$$;
		CREATE TRIGGER check_test_run_audit_order BEFORE INSERT ON audit_event
		FOR EACH ROW EXECUTE FUNCTION check_test_run_audit_order();
	`)
	t.Cleanup(func() {
		execScript(t, f.su, `DROP TRIGGER IF EXISTS check_test_run_audit_order ON audit_event;
			DROP FUNCTION IF EXISTS check_test_run_audit_order();`)
	})
	for _, rec := range []SessionRecord{installed, guest} {
		commandStatus, command := cmdRun(t, f.ownerSrv, rec.ID, "powershell", "system", "Get-Date")
		toolboxStatus, toolbox := tbRun(t, f.ownerSrv, item.ID, rec.ID, item.Version)
		if commandStatus != http.StatusOK || toolboxStatus != http.StatusOK {
			t.Fatalf("request statuses: command %d, toolbox %d", commandStatus, toolboxStatus)
		}
		for _, run := range []struct{ id, command, source string }{
			{command.RequestID, command.Command, "command"}, {toolbox.RequestID, toolbox.Command, "toolbox"},
		} {
			var gotExec, gotKey, tech, source, itemName, itemOwner, itemScope string
			var version int64
			err := f.su.QueryRow(ctx, `SELECT encode(exec_sha256,'hex'), coalesce(encode(device_key_sha256,'hex'),''),
				technician_id::text, source, coalesce(item_name,''), coalesce(item_owner_id::text,''),
				coalesce(item_scope,''), coalesce(item_version,0)
				FROM run_record WHERE request_id = $1`, run.id).
				Scan(&gotExec, &gotKey, &tech, &source, &itemName, &itemOwner, &itemScope, &version)
			if rec.ID == guest.ID {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("attended run query: %v, want no rows", err)
				}
				continue
			}
			wantExec := sha256.Sum256([]byte(run.command))
			if err != nil || gotExec != hex.EncodeToString(wantExec[:]) || gotKey != "" ||
				tech != f.owner || source != run.source {
				t.Fatalf("installed run snapshot: exec=%s key=%s tech=%s source=%s err=%v", gotExec, gotKey, tech, source, err)
			}
			if source == "toolbox" && (itemName != item.Name || itemOwner != f.owner || itemScope != "personal" || version != item.Version) {
				t.Fatalf("toolbox snapshot: %q %q %q %d", itemName, itemOwner, itemScope, version)
			}
		}
	}
	mustExec(t, f.su, `DELETE FROM machine WHERE id = $1`, guestID)
	mustExec(t, f.su, `REVOKE INSERT ON audit_event FROM rmt_app`)
	commandStatus, _ := cmdRun(t, f.ownerSrv, installed.ID, "cmd", "system", "dir")
	toolboxStatus, _ := tbRun(t, f.ownerSrv, item.ID, installed.ID, item.Version)
	mustExec(t, f.su, `GRANT INSERT ON audit_event TO rmt_app`)
	var n int
	err := f.su.QueryRow(ctx, `SELECT count(*) FROM run_record WHERE tenant_id = $1`, f.tenant).Scan(&n)
	if commandStatus != 500 || toolboxStatus != 500 || err != nil || n != 2 {
		t.Fatalf("audit failure rollback: statuses %d/%d, rows %d (%v)", commandStatus, toolboxStatus, n, err)
	}
}

type runReceiptFixture struct {
	*toolboxFixture
	session SessionRecord
	pub     ed25519.PublicKey
	signer  ed25519.PrivateKey
}

func newRunReceiptFixture(t *testing.T) *runReceiptFixture {
	t.Helper()
	f := newToolboxFixture(t)
	applyFleetDirectiveMigration(t, f.su)
	applyMigrationFile(t, f.su, "migrations/0084_wake_on_lan.sql")
	applyMigrationFile(t, f.su, "migrations/0070_directive_final_ack.sql")
	applyMigrationFile(t, f.su, "migrations/0073_directive_forgotten.sql")
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, f.su, `UPDATE machine SET pubkey = $1 WHERE device_id = 'tb-dev'`, []byte(pub))
	mustExec(t, f.su, `UPDATE app_user SET display_name = 'Run Technician' WHERE id = $1`, f.owner)
	return &runReceiptFixture{toolboxFixture: f, session: startRunTestSession(t, f, "tb-dev"), pub: pub, signer: signer}
}

func (f *runReceiptFixture) claims(requestID, command, shell, runAs string) RunReceiptClaims {
	sum := sha256.Sum256([]byte(command))
	code := int32(-17)
	return RunReceiptClaims{TenantID: f.tenant, DeviceID: "tb-dev", SessionID: f.session.ID, RequestID: requestID,
		Shell: shell, RunAs: runAs, ExecSHA256: hex.EncodeToString(sum[:]), Outcome: "exited",
		ExitCode: &code, Truncated: true, FinishedAtMs: time.Now().UnixMilli()}
}

func (f *runReceiptFixture) commandClaims(t *testing.T) RunReceiptClaims {
	t.Helper()
	status, run := cmdRun(t, f.ownerSrv, f.session.ID, "cmd", "system", "dir")
	if status != http.StatusOK {
		t.Fatalf("command request: %d", status)
	}
	return f.claims(run.RequestID, run.Command, run.Shell, run.RunAs)
}

func (f *runReceiptFixture) receipt(t *testing.T, claims RunReceiptClaims) []byte {
	t.Helper()
	preimage, err := runReceiptPreimage(claims)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := json.Marshal(signedRunReceipt{Claims: claims, Sig: hex.EncodeToString(ed25519.Sign(f.signer, preimage))})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func postRunResult(t *testing.T, srv *Server, requestID string, receipt []byte) int {
	t.Helper()
	return apiJSON(t, srv, "POST", "/runs/"+requestID+"/result", `{"receipt":`+string(receipt)+`}`, nil)
}

func TestPgRunReceiptCompletion(t *testing.T) {
	f := newRunReceiptFixture(t)
	ctx := context.Background()
	exited, timedOut, startFailed := f.commandClaims(t), f.commandClaims(t), f.commandClaims(t)
	timedOut.Outcome = "timed_out"
	startFailed.Outcome, startFailed.ExitCode, startFailed.Truncated = "start_failed", nil, false
	mustExec(t, f.su, `UPDATE session_record SET ended_at = clock_timestamp() WHERE id = $1`, f.session.ID)
	for _, claims := range []RunReceiptClaims{exited, timedOut, startFailed} {
		receipt := f.receipt(t, claims)
		if code := postRunResult(t, f.techSrv, claims.RequestID, receipt); code != 404 {
			t.Fatalf("wrong submitter: %d", code)
		}
		if code := postRunResult(t, f.alienSrv, claims.RequestID, receipt); code != 404 {
			t.Fatalf("wrong tenant: %d", code)
		}
		if code := postRunResult(t, f.ownerSrv, claims.RequestID, receipt); code != 200 {
			t.Fatalf("%s: %d", claims.Outcome, code)
		}
		var outcome string
		var exit *int32
		var truncated bool
		var finished, completed time.Time
		var digest, keyHash []byte
		err := f.su.QueryRow(ctx, `SELECT outcome, exit_code, truncated, finished_at, completed_at, receipt_digest,
			device_key_sha256 FROM run_record WHERE request_id = $1`, claims.RequestID).
			Scan(&outcome, &exit, &truncated, &finished, &completed, &digest, &keyHash)
		_, preimage, sig, _ := decodeRunReceipt(receipt)
		wantDigest := sha256.Sum256(append(preimage, sig...))
		wantKey := sha256.Sum256(f.pub)
		if err != nil || outcome != claims.Outcome || truncated != claims.Truncated || finished.UnixMilli() != claims.FinishedAtMs ||
			(exit == nil) != (claims.ExitCode == nil) || (exit != nil && *exit != *claims.ExitCode) ||
			hex.EncodeToString(digest) != hex.EncodeToString(wantDigest[:]) || hex.EncodeToString(keyHash) != hex.EncodeToString(wantKey[:]) {
			t.Fatalf("persisted %s result differs: %v", claims.Outcome, err)
		}
		if code := postRunResult(t, f.ownerSrv, claims.RequestID, append([]byte("  "), receipt...)); code != 200 {
			t.Fatalf("identical retry: %d", code)
		}
		claims.FinishedAtMs++
		if code := postRunResult(t, f.ownerSrv, claims.RequestID, f.receipt(t, claims)); code != 409 {
			t.Fatalf("different retry: %d", code)
		}
		var after time.Time
		var n int
		err = f.su.QueryRow(ctx, `SELECT completed_at, (SELECT count(*) FROM audit_event
			WHERE action = 'command.run_completed' AND target_kind = 'machine' AND target_id::text = $2
			AND metadata->>'request_id' = r.request_id::text AND metadata->>'outcome' = $3
			AND metadata->'truncated' = to_jsonb(r.truncated)
			AND metadata->'exit_code' = coalesce(to_jsonb(r.exit_code), 'null'::jsonb))
			FROM run_record r WHERE request_id = $1::uuid`, claims.RequestID, f.session.MachineID, outcome).Scan(&after, &n)
		if err != nil || !after.Equal(completed) || n != 1 {
			t.Fatalf("retry wrote or audit missing: completed %v -> %v, audit %d (%v)", completed, after, n, err)
		}
	}
}

func TestPgRunReceiptRefusals(t *testing.T) {
	f := newRunReceiptFixture(t)
	mustExec(t, f.su, `UPDATE machine SET pubkey = ''::bytea WHERE id = $1`, f.session.MachineID)
	keyless := f.commandClaims(t)
	mustExec(t, f.su, `UPDATE machine SET pubkey = $2 WHERE id = $1`, f.session.MachineID, []byte(f.pub))
	if code := postRunResult(t, f.ownerSrv, keyless.RequestID, f.receipt(t, keyless)); code != 400 {
		t.Fatalf("keyless request after key was pinned: %d", code)
	}
	claims := f.commandClaims(t)
	if code := apiJSON(t, f.techSrv, "POST", "/runs/"+claims.RequestID+"/result", "{", nil); code != 404 {
		t.Fatalf("wrong submitter with malformed body: %d", code)
	}
	if code := apiJSON(t, f.ownerSrv, "POST", "/runs/"+claims.RequestID+"/result", strings.Repeat(" ", maxSmallJSONBodyBytes+1), nil); code != 413 {
		t.Fatalf("oversize receipt body: %d", code)
	}
	for _, tc := range []struct {
		name   string
		change func(*RunReceiptClaims)
	}{
		{"tenant", func(c *RunReceiptClaims) { c.TenantID = f.other }},
		{"device", func(c *RunReceiptClaims) { c.DeviceID = "another-device" }},
		{"session", func(c *RunReceiptClaims) { c.SessionID = newUUID() }},
		{"request", func(c *RunReceiptClaims) { c.RequestID = newUUID() }},
		{"shell", func(c *RunReceiptClaims) { c.Shell = "powershell" }},
		{"run_as", func(c *RunReceiptClaims) { c.RunAs = "user" }},
		{"exec hash", func(c *RunReceiptClaims) { c.ExecSHA256 = strings.Repeat("0", 64) }},
		{"finished before request", func(c *RunReceiptClaims) { c.FinishedAtMs -= (6 * time.Minute).Milliseconds() }},
		{"finished in future", func(c *RunReceiptClaims) { c.FinishedAtMs += (6 * time.Minute).Milliseconds() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := claims
			tc.change(&changed)
			if code := postRunResult(t, f.ownerSrv, claims.RequestID, f.receipt(t, changed)); code != 400 {
				t.Fatalf("completion refusal: %d", code)
			}
		})
	}
	receipt := f.receipt(t, claims)
	refused := func(label string) {
		t.Helper()
		if code := postRunResult(t, f.ownerSrv, claims.RequestID, receipt); code != 400 {
			t.Fatalf("%s: %d", label, code)
		}
	}
	mustExec(t, f.su, `UPDATE run_record SET requested_at = clock_timestamp() - interval '25 hours' WHERE request_id = $1`, claims.RequestID)
	refused("after 24 hours")
	mustExec(t, f.su, `UPDATE run_record SET requested_at = clock_timestamp() WHERE request_id = $1`, claims.RequestID)
	replacement, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, f.su, `UPDATE machine SET pubkey = $2 WHERE id = $1`, f.session.MachineID, []byte(replacement))
	refused("key replaced")
	mustExec(t, f.su, `UPDATE machine SET pubkey = $2 WHERE id = $1`, f.session.MachineID, []byte(f.pub))
	// A different tenant's removed row carrying the key must also invalidate this run.
	_, otherMachine := seedGroupMachine(t, f.su, f.other, "other-key-row")
	mustExec(t, f.su, `UPDATE machine SET status = 'removed', pubkey = $2 WHERE id = $1`, otherMachine, []byte(f.pub))
	refused("key tombstoned on another row")
	mustExec(t, f.su, `DELETE FROM machine WHERE id = $1`, otherMachine)
	mustExec(t, f.su, `UPDATE machine SET status = 'removed' WHERE id = $1`, f.session.MachineID)
	refused("machine removed")
	var n int
	err = f.su.QueryRow(context.Background(), `SELECT count(*) FROM audit_event WHERE action = 'command.run_completed'`).Scan(&n)
	if err != nil || n != 0 {
		t.Fatalf("refusals wrote completion audit: %d (%v)", n, err)
	}
}

func TestPgRunReceiptForgetLockOrder(t *testing.T) {
	for _, differentMachine := range []bool{false, true} {
		machineCase := "same-machine"
		if differentMachine {
			machineCase = "shared-key"
		}
		for _, completionFirst := range []bool{false, true} {
			order := "forget-first"
			if completionFirst {
				order = "completion-first"
			}
			t.Run(machineCase+"/"+order, func(t *testing.T) {
				f := newRunReceiptFixture(t)
				claims := f.commandClaims(t)
				receipt := f.receipt(t, claims)
				machineID, groupID := f.session.MachineID, f.groupID
				if differentMachine {
					groupID, machineID = seedGroupMachine(t, f.su, f.tenant, "other-key-row")
					mustExec(t, f.su, `UPDATE machine SET pubkey = $2 WHERE id = $1`, machineID, []byte(f.pub))
				}
				mustExec(t, f.su, `UPDATE machine SET status = 'retired' WHERE id = $1`, machineID)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				holder, err := f.su.Acquire(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer holder.Release()
				blocker, err := holder.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback(context.Background())
				if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mgmt_audit_chain:' || $1, 0))`, f.tenant); err != nil {
					t.Fatal(err)
				}
				audit := NewPgMgmtAuditStore(f.app)
				directives := NewPgDirectiveStore(f.app, audit)
				completion, forget := make(chan error, 1), make(chan error, 1)
				startCompletion := func() {
					go func() {
						_, err := audit.completeRun(ctx, f.tenant, f.owner, claims.RequestID, func() ([]byte, error) { return receipt, nil })
						completion <- err
					}()
				}
				startForget := func() {
					go func() {
						_, err := directives.ForgetMachine(ctx, f.tenant, ForgetMachineInput{
							MachineID: machineID, ExpectGroupID: groupID, ActorID: f.owner,
						})
						forget <- err
					}()
				}
				first, second := startForget, startCompletion
				if completionFirst {
					first, second = startCompletion, startForget
				}
				first()
				winnerPID := waitRunLock(t, ctx, f, holder.Conn().PgConn().PID(), "mgmt_audit_chain:")
				second()
				wantWait := "FROM machine"
				if differentMachine {
					wantWait = "devkey:"
				}
				waitRunLock(t, ctx, f, winnerPID, wantWait)
				if err := blocker.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-forget:
					if err != nil {
						t.Fatalf("forget: %v", err)
					}
				case <-ctx.Done():
					t.Fatal("forget did not finish")
				}
				select {
				case err := <-completion:
					if (completionFirst && err != nil) || (!completionFirst && !errors.Is(err, errRunReceiptRefused)) {
						t.Fatalf("completion: %v", err)
					}
				case <-ctx.Done():
					t.Fatal("completion did not finish")
				}
				var completed bool
				if err := f.su.QueryRow(ctx, `SELECT completed_at IS NOT NULL FROM run_record WHERE request_id = $1`, claims.RequestID).
					Scan(&completed); err != nil || completed != completionFirst {
					t.Fatalf("completed: %t (%v)", completed, err)
				}
				if completionFirst {
					if code := postRunResult(t, f.ownerSrv, claims.RequestID, receipt); code != 200 {
						t.Fatalf("identical retry after tombstone: %d", code)
					}
				}
			})
		}
	}
}

func waitRunLock(t *testing.T, ctx context.Context, f *runReceiptFixture, blocker uint32, statement string) uint32 {
	t.Helper()
	wait, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	for {
		var pid int32
		err := f.su.QueryRow(wait, `SELECT pid FROM pg_stat_activity
			WHERE $1 = ANY(pg_blocking_pids(pid)) AND strpos(query, $2) > 0
			AND datname = current_database() LIMIT 1`, int32(blocker), statement).Scan(&pid)
		if err == nil {
			return uint32(pid)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("waiting for %q: %v", statement, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type runWebhookObserver struct {
	WebhookStore
	events chan string
}

func (o runWebhookObserver) ListDeliveriesForEvent(_ context.Context, _, action string) ([]WebhookDelivery, error) {
	o.events <- action
	return nil, nil
}

func TestPgRunHistoryVisibilityAndCompletionWebhooks(t *testing.T) {
	f := newRunReceiptFixture(t)
	_, shared := tbCreate(t, f.ownerSrv, "shared", "Shared snapshot", "cmd", "dir")
	_, personal := tbCreate(t, f.ownerSrv, "personal", "Personal snapshot", "cmd", "whoami")
	requestToolboxRun := func(item tbItem) RunReceiptClaims {
		t.Helper()
		status, run := tbRun(t, f.ownerSrv, item.ID, f.session.ID, item.Version)
		if status != 200 {
			t.Fatalf("toolbox request %q: %d", item.Name, status)
		}
		return f.claims(run.RequestID, run.Command, run.Shell, run.RunAs)
	}
	adHoc := f.commandClaims(t)
	personalRun := requestToolboxRun(personal)
	sharedRun := requestToolboxRun(shared)
	if status := tbUpdate(t, f.ownerSrv, shared.ID, shared.Version, "Renamed", nil); status != 200 {
		t.Fatalf("rename shared item: %d", status)
	}
	mustExec(t, f.su, `DELETE FROM toolbox_item WHERE id = $1`, shared.ID)

	observer := runWebhookObserver{events: make(chan string, 8)}
	f.ownerSrv.Dispatcher = &WebhookDispatcher{Store: observer, Workers: 1}
	t.Cleanup(f.ownerSrv.Dispatcher.Stop)
	for _, run := range []RunReceiptClaims{personalRun, sharedRun} {
		if code := postRunResult(t, f.ownerSrv, run.RequestID, f.receipt(t, run)); code != 200 {
			t.Fatalf("toolbox completion: %d", code)
		}
	}
	if code := postRunResult(t, f.ownerSrv, adHoc.RequestID, f.receipt(t, adHoc)); code != 200 {
		t.Fatalf("command completion: %d", code)
	}
	for _, want := range []string{"toolbox.run_completed", "command.run_completed"} {
		select {
		case got := <-observer.events:
			if got != want {
				t.Fatalf("webhook action %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("missing webhook action %q", want)
		}
	}
	var n int
	if err := f.su.QueryRow(context.Background(), `SELECT count(*) FROM audit_event
		WHERE action = 'toolbox.run_completed' AND target_kind = 'machine' AND target_id = $1`,
		f.session.MachineID).Scan(&n); err != nil || n != 2 {
		t.Fatalf("personal and shared audit events: %d (%v)", n, err)
	}

	type historyPage struct {
		Runs       []runHistoryEntry `json:"runs"`
		NextOffset *int              `json:"next_offset"`
	}
	history := func(srv *Server, path string, wantIDs ...string) historyPage {
		t.Helper()
		var page historyPage
		if code := apiJSON(t, srv, "GET", path, "", &page); code != 200 {
			t.Fatalf("history %s: %d", path, code)
		}
		if len(page.Runs) != len(wantIDs) {
			t.Fatalf("history %s got %+v, want ids %v", path, page.Runs, wantIDs)
		}
		for i, id := range wantIDs {
			if page.Runs[i].RequestID != id {
				t.Fatalf("history %s got %+v, want ids %v", path, page.Runs, wantIDs)
			}
		}
		return page
	}
	groupOther := seedGroup(t, f.su, f.tenant)
	reader := func(viewMachines, viewAudit GroupScope, audit bool) *Server {
		members := []Membership{NewCapabilityMembership([]Capability{CapViewMachines}, viewMachines)}
		if audit {
			members = append(members, NewCapabilityMembership([]Capability{CapViewAudit}, viewAudit))
		}
		return f.serverFor(&Principal{UserID: f.tech, TenantID: f.tenant, SessionID: "sess-" + f.tech,
			Grant: NewGrant(f.tech, f.tenant, members...)})
	}
	machinePath := "/machines/" + f.session.MachineID + "/runs"
	sharedPath := "/toolbox/" + shared.ID + "/runs"
	personalPath := "/toolbox/" + personal.ID + "/runs"
	inScope := reader(AllGroups(), Groups(f.groupID), true)
	for _, path := range []string{machinePath, sharedPath, personalPath} {
		history(reader(AllGroups(), AllGroups(), false), path)
		history(reader(AllGroups(), Groups(groupOther), true), path)
		history(reader(Groups(groupOther), AllGroups(), true), path)
		history(f.alienSrv, path)
	}
	history(inScope, personalPath)
	history(inScope, machinePath, sharedRun.RequestID, adHoc.RequestID)
	history(f.ownerSrv, personalPath, personalRun.RequestID)
	page := history(f.ownerSrv, machinePath+"?limit=1", sharedRun.RequestID)
	if page.NextOffset == nil || *page.NextOffset != 1 {
		t.Fatalf("next page offset: %v", page.NextOffset)
	}
	history(f.ownerSrv, machinePath+"?limit=1&offset=1", personalRun.RequestID)
	row := history(inScope, sharedPath, sharedRun.RequestID).Runs[0]
	if !row.ItemDeleted || row.ItemName != shared.Name || row.ItemVersion == nil || *row.ItemVersion != shared.Version ||
		row.TechnicianName != "Run Technician" || row.RunAs != "system" || row.Result != "exit -17" {
		t.Fatalf("history snapshot: %+v", row)
	}
	mustExec(t, f.su, `UPDATE machine SET group_id = $2 WHERE id = $1`, f.session.MachineID, groupOther)
	history(inScope, machinePath)
	history(inScope, sharedPath)
	history(reader(AllGroups(), Groups(groupOther), true), machinePath, sharedRun.RequestID, adHoc.RequestID)
}
