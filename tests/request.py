import requests
import time
import threading

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

def target_function():
    while True:
        for url in web_list:
            start_time = time.time()
            requests.get(url)
            end_time = time.time()
            print(f"Time Elapsed:{end_time-start_time}")

if __name__ == '__main__':
    t1 = threading.Thread(target=target_function)
    t2 = threading.Thread(target=target_function)
    t3 = threading.Thread(target=target_function)
    t4 = threading.Thread(target=target_function)
    t5 = threading.Thread(target=target_function)
    t6 = threading.Thread(target=target_function)
    t7 = threading.Thread(target=target_function)
    t8 = threading.Thread(target=target_function)
    t9 = threading.Thread(target=target_function)
    t10 = threading.Thread(target=target_function)
    t11 = threading.Thread(target=target_function)
    t12 = threading.Thread(target=target_function)
    t13 = threading.Thread(target=target_function)
    t14 = threading.Thread(target=target_function)
    t15 = threading.Thread(target=target_function)
    t16 = threading.Thread(target=target_function)
    t17 = threading.Thread(target=target_function)
    t18 = threading.Thread(target=target_function)
    t19 = threading.Thread(target=target_function)
    t20 = threading.Thread(target=target_function)
    t1.start()
    t2.start()  
    t3.start()
    t4.start()
    t5.start()
    t6.start()
    t7.start()
    t8.start()
    t9.start()
    t10.start()
    t11.start()
    t12.start()
    t13.start()
    t14.start()
    t15.start()
    t16.start()
    t17.start()
    t18.start()
    t19.start()
    t20.start()
    