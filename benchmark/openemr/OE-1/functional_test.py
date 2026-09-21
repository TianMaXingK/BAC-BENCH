                      
""

import re
import subprocess
import sys
import warnings

import requests

warnings.filterwarnings("ignore")

FUNC_MARKER  = "NO-CVE-1-FUNC-TEST-DB-SENTINEL-c4f9d2e8"
BASE_URL     = "http://192.168.115.88:8081"
TEST_USER    = "test_low"
TEST_PASS    = "Test@12345"
DB_CONTAINER = "mydocker-db-1"
DB_USER      = "root"
DB_PASS      = "root"
DB_NAME      = "openemr"
MSG_URL      = f"{BASE_URL}/interface/main/messages/messages.php"
PROXIES      = {"http": None, "https": None}


def info(msg):  print(f"[*] {msg}")
def ok(msg):    print(f"[+] {msg}")
def warn(msg):  print(f"[-] {msg}")
def fail(msg):  print(f"[!] {msg}")


def db_query(sql):
    ""
    try:
        result = subprocess.run(
            ["docker", "exec", DB_CONTAINER,
             "mysql", f"-u{DB_USER}", f"-p{DB_PASS}", DB_NAME, "-e", sql],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            warn(f"DB query failed: {result.stderr.strip()[:200]}")
            return None
    except Exception as e:
        warn(f"DB query exception: {e}")
        return None


def get_pnote_from_db(pnote_id):
    ""
    sql = f"SELECT id, assigned_to, deleted FROM pnotes WHERE id={pnote_id};"
    output = db_query(sql)
    if output:
        lines = output.strip().split('\n')
        if len(lines) > 1:
            fields = lines[1].split('\t')
            if len(fields) < 3:
                fields = lines[1].split()
            if len(fields) >= 3:
                try:
                    return (int(fields[0]), fields[1], int(fields[2]))
                except:
                    pass
    return None


def db_cleanup():
    ""
    sql = f"UPDATE pnotes SET deleted=1 WHERE body LIKE '%{FUNC_MARKER}%' AND deleted=0;"
    try:
        result = subprocess.run(
            ["docker", "exec", DB_CONTAINER,
             "mysql", f"-u{DB_USER}", f"-p{DB_PASS}", DB_NAME, "-e", sql],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            ok("DB cleanup OK")
        else:
            warn(f"DB cleanup warning: {result.stderr.strip()[:100]}")
    except Exception as e:
        warn(f"DB cleanup failed (non-critical): {e}")


def login(base_url, username, password):
    s = requests.Session()
    s.trust_env = False
    s.proxies = PROXIES
    r = s.post(
        f"{base_url}/interface/main/main_screen.php?auth=login&site=default",
        data={
            "new_login_session_management": "1",
            "languageChoice": "1",
            "authUser": username,
            "clearPass": password,
        },
        verify=False, timeout=15, allow_redirects=True,
    )
    if r.status_code != 200 or "logout" not in r.text.lower():
        fail(f"Login failed for '{username}' (HTTP {r.status_code})")
        sys.exit(1)
    ok(f"Login OK: {username}")
    return s


def get_message_ids(session):
    ""
    r = session.get(MSG_URL, params={"form_active": "1"}, verify=False, timeout=15)
    ids = re.findall(r'name=["\']delete_id\[\]["\'][^>]*value=["\'](\d+)["\']', r.text)
    if not ids:
        ids = re.findall(r'value=["\'](\d+)["\'][^>]*name=["\']delete_id\[\]["\']', r.text)
    return [int(x) for x in ids]


def create_own_message(session, username):
    ""
    r = session.post(
        MSG_URL,
        params={"showall": "", "sortby": "pnotes.date", "sortorder": "desc",
                "begin": "0", "form_active": "1"},
        data={
            "task":                "add",
            "note":                f"{FUNC_MARKER} — safe to delete",
            "noteid":              "",
            "form_note_type":      "Unassigned",
            "form_message_status": "New",
            "reply_to":            "0",
            "assigned_to":         username,
        },
        verify=False, timeout=15, allow_redirects=True,
    )

                       
    sql = f"SELECT id FROM pnotes WHERE body LIKE '%{FUNC_MARKER}%' AND deleted=0 ORDER BY id DESC LIMIT 1;"
    output = db_query(sql)
    if output:
        lines = output.strip().split('\n')
        if len(lines) > 1:
            try:
                return int(lines[1])
            except:
                pass

                                       
    ids = re.findall(r'name=["\']delete_id\[\]["\'][^>]*value=["\'](\d+)["\']', r.text)
    if not ids:
        ids = re.findall(r'value=["\'](\d+)["\'][^>]*name=["\']delete_id\[\]["\']', r.text)
    return max(int(x) for x in ids) if ids else None


def delete_message(session, pnote_id):
    ""
    return session.post(
        MSG_URL,
        params={"showall": "", "sortby": "pnotes.date", "sortorder": "desc",
                "begin": "0", "form_active": "1"},
        data=[("task", "delete"), ("delete_id[]", str(pnote_id))],
        verify=False, timeout=15, allow_redirects=True,
    )


def main():
    print("=" * 65)
    print("No-CVE-1 Functional test v2 (DB Enhanced) — Message Center textDelete")
    print(f"  URL  : {BASE_URL}")
    print(f"  User : {TEST_USER}（Front Office，textPermission）")
    print(f"  Sentinel: {FUNC_MARKER}")
    print("=" * 65)

                 
    info("Pre-cleanup: textDatabasetext ...")
    db_cleanup()

                 
    info("Step 1: text ...")
    sess = login(BASE_URL, TEST_USER, TEST_PASS)

                                   
    info(f"Step 2: CreateTesttext assigned_to={TEST_USER} with sentinel ...")
    pnote_id = create_own_message(sess, TEST_USER)
    if pnote_id is None:
        fail("NonetextCreateTesttext（add FailuretextNonetext ID）")
        print()
        print("Functional test: FAIL")
        sys.exit(1)
    ok(f"TesttextCreation succeeded，pnote_id={pnote_id}")

                                      
    info(f"Step 3: textDatabasetext pnote_id={pnote_id} Status BEFORE delete ...")
    pnote_info_before = get_pnote_from_db(pnote_id)
    if not pnote_info_before:
        fail(f"NonetextDatabasetext pnote_id={pnote_id}")
        db_cleanup()
        print()
        print("Functional test: FAIL")
        sys.exit(1)

    pid_before, assigned_before, deleted_before = pnote_info_before
    print(f"  DB BEFORE: id={pid_before}, assigned_to={assigned_before}, deleted={deleted_before}")

    if deleted_before == 1:
        warn(f"pnote_id={pnote_id} textDelete")
        db_cleanup()
        print()
        print("Functional test: FAIL")
        sys.exit(1)

    if assigned_before != TEST_USER:
        warn(f"pnote_id={pnote_id} assigned_to={assigned_before}，Expectedtext {TEST_USER}")

    ok(f"pnote_id={pnote_id} textDatabasetext (deleted=0)")

                          
    info(f"Step 4: POST task=delete&delete_id[]={pnote_id}（text）...")
    del_resp = delete_message(sess, pnote_id)

    if del_resp.status_code == 403:
        fail(f"Deletetext: HTTP 403（text）")
                 
    elif del_resp.status_code not in (200, 302):
        warn(f"DeleteReturntextExpectedStatus: HTTP {del_resp.status_code}")
    else:
        ok(f"DeleteRequesttext (HTTP {del_resp.status_code})")

                                           
    info(f"Step 5: textDatabasetext pnote_id={pnote_id} Status AFTER delete (PRIMARY CHECK) ...")
    pnote_info_after = get_pnote_from_db(pnote_id)
    if not pnote_info_after:
        fail(f"NonetextDatabasetext pnote_id={pnote_id}（textDelete）")
        db_cleanup()
        print()
        print("Functional test: FAIL")
        sys.exit(1)

    pid_after, assigned_after, deleted_after = pnote_info_after
    print(f"  DB AFTER: id={pid_after}, assigned_to={assigned_after}, deleted={deleted_after}")

    print()
    print("  ┌─ Database Check (PRIMARY) ──────────────────────────────")
    print(f"  │  pnote id      : {pnote_id}")
    print(f"  │  assigned_to   : {assigned_after}")
    print(f"  │  deleted BEFORE: {deleted_before}")
    print(f"  │  deleted AFTER : {deleted_after}")
    print("  └─────────────────────────────────────────────────────────")
    print()

    if deleted_after == 0:
        fail(f"DATABASE: pnote_id={pnote_id} textStatus (deleted=0)")
        fail("textDelete（ownership Checktext）")
        db_cleanup()
        print()
        print("Functional test: FAIL")
        sys.exit(1)
    elif deleted_after == 1:
        ok(f"DATABASE CONFIRMS: pnote_id={pnote_id} deleted (deleted=1)")
    else:
        warn(f"DATABASE: unexpected deleted={deleted_after}")

                                          
    info("Step 6: text Web text (SECONDARY CHECK) ...")
    ids_after = get_message_ids(sess)
    still_in_ui = pnote_id in ids_after

    print("  ┌─ Web Interface Check (SECONDARY) ───────────────────────")
    print(f"  │  pnote id={pnote_id} visible in UI: {'YES' if still_in_ui else 'NO'}")
    print(f"  │  Total messages in inbox: {len(ids_after)}")
    print("  └─────────────────────────────────────────────────────────")
    print()

    if still_in_ui:
        warn(f"WEB UI: pnote_id={pnote_id} text inbox text（text）")

          
    print("=" * 65)
    if deleted_after == 1:
        print("Functional test: PASS")
        print("  ✓ DATABASE PRIMARY CHECK: deleted=1")
        print("  textUsertextNormalDeletetext inbox text（text）")
        print("=" * 65)
        sys.exit(0)
    else:
        print("Functional test: FAIL")
        print("  ✗ DATABASE PRIMARY CHECK: deleted=0")
        print("  text，textDeletetext")
        print("=" * 65)
        sys.exit(1)


if __name__ == "__main__":
    main()
