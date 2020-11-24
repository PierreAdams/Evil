# Evil Ransomware 
(Based on Forensic - DGSE Challenge https://challengecybersec.fr  )

``` 
$ file dump.vmem  
dump.vmem: data
```

vmem extention is a Vmware dump, we can use [Volatility](https://github.com/volatilityfoundation/volatility) tools to extract some information from file    

first : determine profile : 
``` 
$ volatility -f dump.vmem -h imageinfo   
          Suggested Profile(s) : Win7SP1x64
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002c4c0a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002c4dd00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-10-05 11:17:37 UTC+0000
     Image local date and time : 2020-10-05 13:17:37 +0200

```
Second, inspect dump with the profile we find :  
Inspect processus :   
``` 
$ volatility -f dump.vmem --profile=Win7SP1x64 pstree
```
Inspect all tcp Connections/Sockets
``` 
$ volatility -f dump.vmem --profile=Win7SP1x64 netscan
```
Some example : [Volatility Cheat Sheet](https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf)

If we search command line in execution : we have interesting return
```
$ volatility -f dump.vmem --profile=Win7SP1x64 cmdline
..............
Command line : "C:\Users\user\AppData\Local\Drpbx\drpbx.exe" C:\Users\user\Documents\Firefox_installer.exe
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\user\Documents\informations_attaque.txt.evil
.............
```
If we  search all file : .evil 
```
$ volatility -f dump.vmem --profile=Win7SP1x64 filescan | grep evil
Volatility Foundation Volatility Framework 2.6.1
0x000000001715ed50     16      0 R--r-- \Device\HarddiskVolume1\Users\user\Documents\informations_attaque.txt.evil
0x000000003fa3ebc0      2      0 RW-r-- \Device\HarddiskVolume1\ProgramData\Microsoft\RAC\PublishedData\RacWmiDatabase.sdf.evil                              
0x000000003fac8d10     32      0 RW-r-- \Device\HarddiskVolume1\ProgramData\Microsoft\Windows\WER\ReportQueue\NonCritical_Firefox_installe_d514681bfc376345742b2157ace1e72c17fd991_cab_0938b7ba\appcompat.txt.evil                                                                                                        
0x000000003fad8620     16      0 RW-r-- \Device\HarddiskVolume1\Users\user\AppData\Local\Microsoft\Windows\Caches\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000002.db.evil            
```
After some research about ".evil" extention   

we can find evil is French Ransomware based on jigsaw : with this text : 
>Que les choses soient bien claires, nous ne tolérons aucune entrave à notre plan
Votre action de résistance est vaine et dénuée de sens
Nous vous détruirons sans pitié, vous et vos idées révolutionnaires,
Vous avez peut-être deviné notre plan, mais vous ne parviendrez pas à le transmettre à la coalition internationale,
Vos preuves ont été chiffrées et sont désormais inaccessibles mouhahahaha,
Vous pouvez toujours essayer de payer la rançon, vous ne retrouverez rien
Envoyez EvilCoins ici:

![](https://github.com/PierreAdams/Evil/blob/main/evil.png)

if we extract screenshot on dump file
```
$ volatility -f dump.vmem --profile=Win7SP1x64 screenshot --dump-dir .
$ ristretto session_1.WinSta0.Default.png 
```
we can see :  
<img src="https://github.com/PierreAdams/Evil/blob/main/evil2.png" width="600" />

Now it's time to analyse : "drpbx.exe"
drpbx.exe and firefox.exe are  often source of this ransomware
```
$ volatility -f dump.vmem --profile=Win7SP1x64 pslist
.....................
0xfffffa8000e91b30 drpbx.exe              2304   2916      8      149      1      0 2020-10-05 11:17:01 UTC+0000                                 
......................
$ volatility -f dump.vmem --profile=Win7SP1x64 procdump -p 2304 --dump-dir .
```
we can use this website tools : [VirusTotal](https://www.virustotal.com/gui/)   

![](https://github.com/PierreAdams/Evil/blob/main/evil3.png)

we see this programme is a malicious exec with a 36 score point   
like jigsaw, Evil is write in .NET   

there are several tools avalaible for decompile .NET program  
i will use DotPeek on Windows :     

![](https://github.com/PierreAdams/Evil/blob/main/evil4.PNG)     
Import exec file :     

![](https://github.com/PierreAdams/Evil/blob/main/evil5.PNG)

now we can see the source code of this executable:   
![](https://github.com/PierreAdams/Evil/blob/main/evil6.PNG)

with code source we can see the algorithm use : 
AES   

in this case 2 things interest us : 
 - Password Encryption 
 - Initialization Vector 
 we find this information in the source code:   
![](https://github.com/PierreAdams/Evil/blob/main/evil7.PNG)
___________________________________________
![](https://github.com/PierreAdams/Evil/blob/main/evil8.PNG)
___________________________________________


``` 
$ echo "RXZpbERlZmF1bHRQYXNzIQ==" | base64 -d 
EvilDefaultPass!
```

Once we have password and IV we can now decrypt interesting file : 
```
$ volatility -f dump.vmem --profile=Win7SP1x64 filescan | grep evil
  0x000000001715ed50     16      0 R--r-- \Device\HarddiskVolume1\Users\user\Documents\informations_attaque.txt.evil
$ volatility -f dump.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000001715ed50 -D .
```
for decrypt aes cbc with iv and keypass i use this website tools :  [CyberChef](https://gchq.github.io/CyberChef)     
![](https://github.com/PierreAdams/Evil/blob/main/evil9.png)

___________________________________________
