# CVE-2023-36723

This is PoC for arbitrary directory creation bug in Container Manager service.

This PoC is not thoroughly tested so it may not even work most of the time (it was enough for msrc to confirm vulnerability).

In order to exploit this vulnerability a Windows Sandbox feature have to be installed on windows host.

When Windows Sandbox feature is installed a set of directories will be created in c:\programdata directory.
One of those directories is C:\ProgramData\Microsoft\Windows\Containers\BaseImages\\<GUID\>\BaseLayer. 
This directory is different as it gives authenticated users group modify permissions on all child objects.

![1](https://github.com/Wh04m1001/CVE-2023-36723/blob/main/1.png)


If BaseLayer directory is empty or some of directories inside it are removed, next time when Windows sandbox is started,  a process cmimageworker.exe will recreate those directories/files  without checking for symbolic links and set DACL that allows authenticated users to modify them.

![2](https://github.com/Wh04m1001/CVE-2023-36723/blob/main/2.png)

I have create PoC that will abuse this vulnerability to create directory pwn with permissive DACL's inside c:\windows\system32 directory as show below:

![poc](https://github.com/Wh04m1001/CVE-2023-36723/blob/main/poc.png)

An attacker can abuse this vulnerability to execute code in process that is running with SYSTEM privileges by abusing SxS assembly loading.
