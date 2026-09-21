                      
""

import sys
import re
import subprocess
import requests
from bs4 import BeautifulSoup

BASE_URL     = "http://192.168.115.88:8800"
REPO_PATH    = "/home/ground/Desktop/BAC/cve-app/bookwyrm/bookwyrm"
COMPOSE_FILE = f"{REPO_PATH}/docker-compose.yml"
COMPOSE_OVR  = f"{REPO_PATH}/docker-compose.override.yml"

TEST_LIST_NAME = "FuncTest_List_textVerify"

CREATOR_LOCALNAME = "usera"
CREATOR_PASSWORD  = "userApass1"
OTHER_LOCALNAME   = "userb"
OTHER_PASSWORD    = "userBpass1"


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


def login(localname, password):
    session = requests.Session()
    csrf = get_csrf(session, BASE_URL + "/login/")
    if not csrf:
        return None, None
    session.post(BASE_URL + "/login/", data={
        "csrfmiddlewaretoken": csrf,
        "localname": localname,
        "password":  password,
    }, allow_redirects=True)
    if "sessionid" not in session.cookies:
        return None, None
    return session, session.cookies.get("csrftoken")


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


def cleanup_test_lists():
    ""
    run_shell(f"""
from bookwyrm.models import List
n, _ = List.objects.filter(name='{TEST_LIST_NAME}').delete()
print(f'cleaned={{n}}')
""")


def test_normal_list_creation():
    ""
    session_c, _ = login(CREATOR_LOCALNAME, CREATOR_PASSWORD)
    if not session_c:
        return False, "CreationLogin failed"

    session_o, _ = login(OTHER_LOCALNAME, OTHER_PASSWORD)
    if not session_o:
        return False, "textLogin failed（textGetCreation ID）"

    creator_id = get_user_id(session_o, CREATOR_LOCALNAME)
    if not creator_id:
        return False, f"NonetextCreation {CREATOR_LOCALNAME} text ID"

    session_c.get(BASE_URL + "/")
    csrf = session_c.cookies.get("csrftoken")

    resp = session_c.post(
        f"{BASE_URL}/list",
        data={
            "csrfmiddlewaretoken": csrf,
            "user":        creator_id,
            "name":        TEST_LIST_NAME,
            "description": "Functional testtextCreate",
            "curation":    "closed",
            "privacy":     "public",
        },
        allow_redirects=False,
    )

    if resp.status_code != 302:
        return False, f"CreationReturntext 302（Actual：{resp.status_code}）"

    lines = run_shell(f"""
from bookwyrm.models import List, User
creator = User.objects.get(localname='{CREATOR_LOCALNAME}')
lst = List.objects.filter(name='{TEST_LIST_NAME}').order_by('-id').first()
if lst is None:
    print('LIST_NOT_FOUND')
elif lst.user_id == creator.id:
    print('OWNER_CORRECT')
else:
    other = getattr(lst.user, 'localname', str(lst.user_id))
    print(f'OWNER_WRONG:{{other}}')
""")

    verdict = next((l for l in lines
                    if l in ("LIST_NOT_FOUND", "OWNER_CORRECT") or l.startswith("OWNER_WRONG")),
                   "UNKNOWN")

    if verdict == "OWNER_CORRECT":
        return True, f"textCreation succeeded，List.user == {CREATOR_LOCALNAME}（DB Verifytext）"
    elif verdict == "LIST_NOT_FOUND":
        return False, "302 ResponsetextWrite DB"
    elif verdict.startswith("OWNER_WRONG"):
        actual = verdict.split(":", 1)[-1]
        return False, f"textownerError，expected {CREATOR_LOCALNAME}，Actual {actual}"
    else:
        return False, f"DB textResulttext: {lines}"


def main():
    print("=" * 56)
    print("  Functional test - BW-3: List Creation")
    print("=" * 56)

    ok = False
    try:
        ok, msg = test_normal_list_creation()
        result = "PASS" if ok else "FAIL"
        print(f"\n[{result}] {msg}")
    finally:
        cleanup_test_lists()

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
