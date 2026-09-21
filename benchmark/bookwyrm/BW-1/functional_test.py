                      
""

import sys
import subprocess
import requests
from bs4 import BeautifulSoup

BASE_URL = "http://192.168.115.88:8800"
REPO_PATH = "/home/ground/Desktop/BAC/cve-app/bookwyrm/bookwyrm"
COMPOSE_FILE = f"{REPO_PATH}/docker-compose.yml"
COMPOSE_OVERRIDE = f"{REPO_PATH}/docker-compose.override.yml"

TEST_MESSAGE_KEYWORD = "FuncTest_DM_textVerify"

                                 
SENDER_LOCALNAME = "usera"
SENDER_PASSWORD  = "userApass1"
RECEIVER_LOCALNAME = "userb"


def get_csrf(session, url):
    resp = session.get(url)
    resp.raise_for_status()
    return session.cookies.get("csrftoken")


def login(localname, password):
    session = requests.Session()
    csrf = get_csrf(session, BASE_URL + "/login/")
    if not csrf:
        return None, None
    session.post(BASE_URL + "/login/", data={
        "csrfmiddlewaretoken": csrf,
        "localname": localname,
        "password": password,
    }, allow_redirects=True)
    if "sessionid" not in session.cookies:
        return None, None
    return session, session.cookies.get("csrftoken")


def run_shell(code):
    ""
    cmd = [
        "docker", "compose",
        "-f", COMPOSE_FILE,
        "-f", COMPOSE_OVERRIDE,
        "exec", "-T", "web",
        "python", "manage.py", "shell", "-c", code,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_PATH)
    return [l for l in result.stdout.splitlines()
            if l.strip() and "warning" not in l.lower() and "warn" not in l.lower()]


def get_user_id(session, localname):
    ""
    resp = session.get(f"{BASE_URL}/user/{localname}")
    if resp.status_code != 200:
        return None
    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup.find_all(True):
        for attr in ("action", "href"):
            val = tag.get(attr, "")
            for kw in ("/block/", "/unblock/", "/report/"):
                if kw in val:
                    candidate = val.strip("/").split("/")[-1]
                    if candidate.isdigit():
                        return int(candidate)
    return None


def cleanup_test_messages():
    ""
    run_shell(f"""
from bookwyrm.models import Status
n, _ = Status.objects.filter(
    privacy='direct',
    content__contains='{TEST_MESSAGE_KEYWORD}'
).delete()
print(f'cleaned={{n}}')
""")


def test_normal_dm_send_and_deliver():
    ""
                   
    session_s, _ = login(SENDER_LOCALNAME, SENDER_PASSWORD)
    if not session_s:
        return False, "SendtextLogin failed"

                                             
    receiver_id = get_user_id(session_s, RECEIVER_LOCALNAME)
    if not receiver_id:
        return False, f"NonetextReceivetext {RECEIVER_LOCALNAME} text ID"

                         
                                                  
    session_r, _ = login(RECEIVER_LOCALNAME, "userBpass1")
    if not session_r:
        return False, "ReceivetextLogin failed（textGetSendtext ID）"
    sender_id = get_user_id(session_r, SENDER_LOCALNAME)
    if not sender_id:
        return False, f"NonetextSendtext {SENDER_LOCALNAME} text ID"

                
    session_s.get(BASE_URL + "/")
    csrf = session_s.cookies.get("csrftoken")

                  
    resp = session_s.post(f"{BASE_URL}/post/direct", data={
        "csrfmiddlewaretoken": csrf,
        "user":            sender_id,
        "content":         f"@{RECEIVER_LOCALNAME} {TEST_MESSAGE_KEYWORD}",
        "content_warning": "",
        "privacy":         "direct",
    }, allow_redirects=False)

    if resp.status_code != 302:
        return False, f"SendtextRequestReturntext 302（Actual：{resp.status_code}）"

                                 
    lines = run_shell(f"""
from bookwyrm.models import Status, User
receiver = User.objects.get(localname='{RECEIVER_LOCALNAME}')
s = Status.objects.filter(
    privacy='direct', deleted=False,
    content__contains='{TEST_MESSAGE_KEYWORD}'
).order_by('-id').first()
if s is None:
    print('STATUS_NOT_FOUND')
elif receiver in s.mention_users.all():
    print('DELIVERED')
else:
    print('NOT_DELIVERED')
""")

    verdict = next((l for l in lines if l in ("DELIVERED", "NOT_DELIVERED", "STATUS_NOT_FOUND")), "UNKNOWN")
    if verdict == "DELIVERED":
        return True, f"textNormaltext {RECEIVER_LOCALNAME} text mention_users"
    elif verdict == "NOT_DELIVERED":
        return False, "textCreationReceivetext mention_users（text block ChecktextNormaltext）"
    elif verdict == "STATUS_NOT_FOUND":
        return False, "textWriteDatabase"
    else:
        return False, f"DB textResulttext: {lines}"


def main():
    print("=" * 56)
    print("  Functional test - BW-1: Direct Message Creation")
    print("=" * 56)

    try:
        ok, msg = test_normal_dm_send_and_deliver()
        result = "PASS" if ok else "FAIL"
        print(f"\n[{result}] {msg}")
    finally:
                             
        cleanup_test_messages()

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
