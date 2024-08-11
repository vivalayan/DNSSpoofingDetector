import socket
import ipaddress
import geoip2.database
import urllib.request
import urllib.error
import json
import struct
import binascii
import ssl
import requests
import csv
import re

DEFAULT_PORT = 4433

# 请求类型常量值
BRANCH_SERVER_ADDRESS_QUERY = 0
BRANCH_SERVER_ADDRESS_ANSWER = 1
VERIDNS_REQUEST = 2
VERIDNS_RESPONSE = 3

# 数据长度常量值
HEADER_TOTAL = 12
HEADER_TYPE = 4
HEADER_LENGTH = 4
HEADER_SEQNUM = 4
BODY_NUMOFADDR = 4
REQBODY_DOMAINNAME = 256
VERIFICATION = 1
LENGTH_IPV4 = 4

# BRANCH_SERVER_TABLE: tuple('Country_name',ip.addr)
# 分支服务器IP地址表
BRANCH_SERVER_TABLE = [
    ['Hong Kong', '20.239.49.221'],
    ['China', '47.120.36.211'],
    # ['Singapore', '192.168.43.102']
    ['Singapore', '20.239.49.221']
    # ['Singapore', '172.25.110.177']
    # ['Singapore', '137.132.84.21']
]


# 查询IP地址
def is_ip_in_prefixes(ip, prefixes):
    for prefix in prefixes:
        if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(prefix):
            return True
    return False

# 查询IP地址（多个IP）
def are_ips_in_prefixes(ip_list, prefixes):
    for ip in ip_list:
        if not is_ip_in_prefixes(ip, prefixes):
            return False
    return True

# 通过分支服务器名称查询分支服务器IP地址
def lookup_branch_ip(branch_name):
    for branch in BRANCH_SERVER_TABLE:
        if branch[0] == branch_name:
            return branch[1]
    return '20.239.49.221'


def handle_client(sock, client_address, client_port):
    # 接收客户端的数据包
    data = b''

    # 由于采用非阻塞Socket，所以需要循环接收数据
    recv_data = sock.recv(HEADER_TOTAL)
    data += recv_data
    hex_SequenceNumber = data[HEADER_TYPE + HEADER_LENGTH:HEADER_TOTAL]
    dec_Type = int.from_bytes(data[:HEADER_TYPE], byteorder='big')

    # Google Open IP List
    url = "https://www.gstatic.com/ipranges/goog.json"
    response = requests.get(url)
    data = json.loads(response.text)
    ipv4_prefixes = []
    for prefix in data["prefixes"]:
        if "ipv4Prefix" in prefix:
            ipv4_prefixes.append(prefix["ipv4Prefix"])

    # Microsoft Open IP List
    with open('./Resources/msft-public-ips.csv', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ipv4_prefixes.append(row['Prefix'])

    # GitHub Open IP List
    with open('./Resources/github.txt', 'r') as f:
        data = json.load(f)
    for key in data:
        if isinstance(data[key], list):
            for item in data[key]:
                match = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})', item)
                if match:
                    ipv4_prefixes.append(match.group())

    # Fastly Open IP List
    response = requests.get('https://api.fastly.com/public-ip-list')
    if response.status_code == 200:
        data = json.loads(response.content)
        ipv4_prefixes += data['addresses']

    # Cloud Flare Open IP List
    response = requests.get('https://www.cloudflare.com/ips-v4')
    if response.status_code == 200:
        data = response.text.strip()
        ipv4_prefixes += data.split('\n')

    # Facebook Open IP List
    with open('./Resources/facebook.txt', 'r') as f:
        for line in f:
            # 删除行末尾的换行符
            line = line.strip()
            # 将行添加到地址列表中
            ipv4_prefixes.append(line)
            
            
# 如果请求类型为0，则进行分支服务器地址查询
    if dec_Type == 0:
        print('''
██████╗  ██████╗  ██████╗ ████████╗
██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
██████╔╝██║   ██║██║   ██║   ██║   
██╔══██╗██║   ██║██║   ██║   ██║   
██║  ██║╚██████╔╝╚██████╔╝   ██║   
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   
                                   
''')
        # 查询客户端所在地址，对应找到最近的分支服务器地址
        print("[*] Request type = Branch Server Address Query")

        # 通过GeoLite2数据库查询客户端所在国家
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        ret = reader.city(client_address[0])
        cli_ip_country = ret.country.name
        # cli_ip_country = 'Singapore'

        # 构造响应数据包
        Response = b''
        
        # 响应类型
        Re_Type = b'\x00\x00\x00\x01'
        
        # 响应序列号
        Re_SeqNum = hex_SequenceNumber
        
        # 分支服务器地址数量
        Re_NumberOfAddr = b'\x00\x00\x00\x01'
        
        # 分支服务器地址
        Re_BranchIPAddr = socket.inet_aton(lookup_branch_ip(cli_ip_country))
        # Re_BranchIPAddr = socket.inet_aton('192.168.43.195')
        # print(Re_BranchIPAddr)
        
        # 响应数据包长度。由于响应数据包中的数据长度为固定值，因此直接计算长度即可
        Re_Length = b'\x00\x00\x00\x14'
        Response = Re_Type + Re_Length + Re_SeqNum + Re_NumberOfAddr \
                   + Re_BranchIPAddr
        print("[*] You are in " + cli_ip_country + ".")
        print("[*] Branch-Server-Answer: Branch Server in "
              + cli_ip_country + " is at " + lookup_branch_ip(cli_ip_country) + ".")

        # 发送响应数据包
        sock.send(Response)
        
        # 关闭Socket
        sock.close()

    elif dec_Type == 2:


        print("[*] Request type = VeriDNS Request")
        data = b''
        #非阻塞Socket，所以需要循环接收数据
        recv_data = sock.recv(REQBODY_DOMAINNAME + BODY_NUMOFADDR)
        data += recv_data

        hex_DomainName = data[:REQBODY_DOMAINNAME]
        hex_NumberOfAddr = data[REQBODY_DOMAINNAME:REQBODY_DOMAINNAME + BODY_NUMOFADDR]
        
        # 提取地址数量并转换为int类型
        dec_NumberOfAddr = int.from_bytes(hex_NumberOfAddr, byteorder='big')

        # 这里清空data，方便根据常量计算接收长度
        data = b''
        
        #非阻塞Socket，循环接收数据
        recv_data = sock.recv(LENGTH_IPV4 * dec_NumberOfAddr)
        data += recv_data
        
        # 根据常量进行切片
        hex_IPAddress = data[:LENGTH_IPV4 * dec_NumberOfAddr]
        str_DomainName = hex_DomainName.decode("utf-8")
        
        # 去除末尾的空字符
        DomainName = str_DomainName.strip('\x00')
        
        # 提取IP地址列表
        list_IPAddress = [socket.inet_ntoa(hex_IPAddress[i * LENGTH_IPV4:i * LENGTH_IPV4 + LENGTH_IPV4]) for i in
                          range(dec_NumberOfAddr)]
        
        print("[*] Verifying DomainName= " + DomainName + "...")
        
        # 如果IP地址在Google、Microsoft、GitHub、Fastly、Cloud Flare、Facebook的公开IP列表中，则返回True
        if are_ips_in_prefixes(list_IPAddress, ipv4_prefixes):
            Verification = b'\x01'
            list_MaliciousIP = []
            hex_byte_list_MaliciousIP = b''
            
        # 否则，进行DNS查询（核心步骤）
        else:
            # Google DNS Request API
            data_google = []
            url = "https://dns.google/resolve?name=" + DomainName + "&type=1"
            try:
                response_google = urllib.request.urlopen(url)
                
            # 如果Google DNS服务不可用，则尝试其他服务
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print("[X] Google DNS Service UNAVAILABLE, trying another one...")
                else:
                    raise
            
            # 如果Google DNS服务可用，则解析JSON数据
            else:
                ret_DNS_json_google = response_google.read().decode('utf-8')
                json_str = ret_DNS_json_google
                data_google_json = json.loads(json_str)
                data_google = [answer['data'] for answer in data_google_json['Answer'] if answer['type'] == 1]

            # CloudFlare DNS Request API
            data_cloudflare = []
            url = "https://cloudflare-dns.com/dns-query"
            params = {"name": DomainName, "type": "A"}
            headers = {"accept": "application/dns-json"}
            try:
                response_cloudflare = requests.get(url, params=params, headers=headers)
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print("[X] Cloud Flare DNS Service UNAVAILABLE, trying another one...")
                else:
                    raise
            else:
                data_cloudflare_json = json.loads(response_cloudflare.text)
                data_cloudflare = [a['data'] for a in data_cloudflare_json['Answer'] if a['type'] == 1]

            # Alibaba DNS Request API
            data_alibaba = []
            url = "https://dns.alidns.com/resolve?name=" + DomainName + "&type=1"
            try:
                response_alibaba = urllib.request.urlopen(url)
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print("[X] Alibaba DNS Service UNAVAILABLE, trying another one...")
                else:
                    raise
            else:
                ret_DNS_json_alibaba = response_alibaba.read().decode('utf-8')
                data_alibaba_json = json.loads(ret_DNS_json_alibaba)
                data_alibaba = [a['data'] for a in data_alibaba_json['Answer'] if a['type'] == 1]

            # 9.9.9.9 DNS Request API
            data_quadnine = []
            url = "https://9.9.9.9:5053/dns-query?name=" + DomainName + "&type=1"
            try:
                response_quadnine = urllib.request.urlopen(url)
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print("[X] 9.9.9.9 DNS Service UNAVAILABLE, trying another one...")
                else:
                    raise
            else:
                ret_DNS_json_quadnine = response_quadnine.read().decode('utf-8')
                data_quadnine_json = json.loads(ret_DNS_json_quadnine)
                data_quadnine = [a['data'] for a in data_quadnine_json['Answer'] if a['type'] == 1]

            # quadnine DNS Request API
            data_quadnine_sec = []
            url = "https://dns.quad9.net:5053/dns-query?name=" + DomainName + "&type=1"
            try:
                response_quadnine_sec = urllib.request.urlopen(url)
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print("[X] Quad9 DNS Service UNAVAILABLE, trying another one...")
                else:
                    raise
            else:
                ret_DNS_json_quadnine_sec = response_quadnine_sec.read().decode('utf-8')
                data_quadnine_json_sec = json.loads(ret_DNS_json_quadnine_sec)
                data_quadnine_sec = [a['data'] for a in data_quadnine_json_sec['Answer'] if a['type'] == 1]

            # DNS10 DNS Request API
            data_dns_ten = []
            url = "https://dns10.quad9.net:5053/dns-query?name=" + DomainName + "&type=1"
            try:
                response_dns_ten = urllib.request.urlopen(url)
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print("[X] DNS10 Service UNAVAILABLE, trying another one...")
                else:
                    raise
            else:
                ret_DNS_json_dns_ten = response_dns_ten.read().decode('utf-8')
                data_dns_ten_json_sec = json.loads(ret_DNS_json_dns_ten)
                data_dns_ten = [a['data'] for a in data_dns_ten_json_sec['Answer'] if a['type'] == 1]

            # DNS11 DNS Request API
            data_dns_elev = []
            url = "https://dns11.quad9.net:5053/dns-query?name=" + DomainName + "&type=1"
            try:
                response_dns_elev = urllib.request.urlopen(url)
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print("[X] DNS11 Service UNAVAILABLE, trying another one...")
                else:
                    raise
            else:
                ret_DNS_json_dns_elev = response_dns_elev.read().decode('utf-8')
                data_dns_elev_json = json.loads(ret_DNS_json_dns_elev)
                data_dns_elev = [a['data'] for a in data_dns_elev_json['Answer'] if a['type'] == 1]

            # de-dus DNS Request API
            data_de_dus = []
            url = "https://de-dus.doh.sb/dns-query?name=" + DomainName + "&type=1"
            try:
                response_de_dus = urllib.request.urlopen(url)
            except urllib.error.HTTPError as e:
                if e.code == 503:
                    print("[X] de-dus Service UNAVAILABLE, trying another one...")
                else:
                    raise
            else:
                ret_DNS_json_de_dus = response_de_dus.read().decode('utf-8')
                data_de_dus_json = json.loads(ret_DNS_json_de_dus)
                data_de_dus = [a['data'] for a in data_de_dus_json['Answer'] if a['type'] == 1]


            # 将所有服务的IP地址合并并去重
            authed_list_IPAddress = list(set(data_alibaba + data_cloudflare + data_quadnine +
                                             data_google + data_quadnine_sec + data_dns_ten +
                                             data_de_dus + data_dns_elev))

            # 查询可能的恶意IP地址
            list_MaliciousIP = [ip for ip in list_IPAddress if ip not in authed_list_IPAddress]

            # 返回验证结果
            Verification = b'\x01' if len(list_MaliciousIP) == 0 else b'\x00'

            # 将恶意IP地址列表转换为字节流
            hex_byte_list_MaliciousIP = b''
            for ip in list_MaliciousIP:
                hex_byte_list_MaliciousIP += binascii.unhexlify(
                    ''.join(['{:02x}'.format(int(x)) for x in ip.split('.')]))

        # 构造应答数据包
        Re_Type = b'\x00\x00\x00\x03'
        Re_SeqNum = hex_SequenceNumber
        Re_Verification = Verification
        Re_NumberOfAddr = struct.pack('I', len(list_MaliciousIP))[::-1]
        Re_MaliciousIP = hex_byte_list_MaliciousIP
        Re_Length = len(Re_Type + Re_SeqNum + Re_Verification + Re_NumberOfAddr + Re_MaliciousIP)
        Response = Re_Type + struct.pack('>I',
                                         Re_Length) + Re_SeqNum + Re_Verification + Re_NumberOfAddr + Re_MaliciousIP
        if Verification == b'\x01':
            Verification_status = "True"
            print("[*] Verification Result = " + Verification_status + "!")
        else:
            Verification_status = "False"
            print("[*] Verification Result = " + Verification_status + "!")
            print("[*] ALERT! POTENTIAL DNS SPOOFING ATTACK DETECTED!")
            print("[*] MALICIOUS DNS A RECORD(S) LIST:")
            # print("[*] {:<10} {:>2}".format(DomainName, list_MaliciousIP))
            print(list_MaliciousIP)

        # Socket发送应答数据包
        sock.send(Response)
        
        # 关闭Socket
        sock.close()
    else:
        pass


def start_server(port=DEFAULT_PORT):
    # socket开启服务
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', port)
    
    # 绑定SSL证书
    sock.bind(server_address)

    # SSL证书
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

    # 加载SSL证书
    context.load_cert_chain('./SSL_Certs/server_cert.crt', './SSL_Certs/server_key.key')

    # 开始服务
    sock.listen(10000)
    print(f"[*] VeriDNS-Server is listening on port {port}...")

    # 等待客户端连接
    while True:
        client_socket, client_address = sock.accept()

        # 将Socket包装为SSL Socket
        ssl_sock = context.wrap_socket(client_socket, server_side=True)
        print("**********************************************************************************")
        print(f"[*] Got connection from {client_address}")

        # 处理客户端请求
        handle_client(ssl_sock, client_address, client_socket)

        # 关闭连接
        client_socket.close()


if __name__ == '__main__':
    print('''
██╗   ██╗███████╗██████╗ ██╗██████╗ ███╗   ██╗███████╗      ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
██║   ██║██╔════╝██╔══██╗██║██╔══██╗████╗  ██║██╔════╝      ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
██║   ██║█████╗  ██████╔╝██║██║  ██║██╔██╗ ██║███████╗█████╗███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██║  ██║██║╚██╗██║╚════██║╚════╝╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
 ╚████╔╝ ███████╗██║  ██║██║██████╔╝██║ ╚████║███████║      ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝      ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
                                                                                                             
''')
    start_server()
