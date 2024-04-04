import requests

web_list = [
    'https://www.google.com',
    'https://www.iovisor.org',
    'https://www.linux.org',
    'https://opensource.com',
    'https://www.facebook.com',
    'https://www.amazon.com',
    'https://www.llvm.org',
    'https://www.instagram.com',
    'https://linuxmint.com',
    'https://www.linux.com',
    'https://ubuntu.com',
    'https://www.redhat.com',
    'https://www.hackerrank.com',
    'https://www.codeforces.com',
    'https://www.codechef.com'
]


for i in range(400):
    for url in web_list:
        requests.get(url)


        

