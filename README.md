# Evil Ransomware 
(Based on DGSE Challenge https://challengecybersec.fr  )

``` 
$ file dump.vmem  
dump.vmem: data
```

after somme research vmem extention is a dump's Vmware Workstation   
We can use [Volatility](https://github.com/volatilityfoundation/volatility) tools to extract some information from file    

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
[Volatility Cheat Sheet](https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf)

If we search command line in execution : we have interesting return
```
$ volatility -f dump.vmem --profile=Win7SP1x64 netscan
..............
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
![](https://github.com/PierreAdams/Evil/blob/main/evil2.png?v=4&s=200)

