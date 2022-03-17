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
