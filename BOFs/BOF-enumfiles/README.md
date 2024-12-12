# BOF-enumfiles
C++ implementation of a BOF to quickly enumerate local files of interest for post-exploitation. Useful to help find potential LOLbins, remoting software, browser or web server installations, etc.<br />

Kind of a dumb script, just meant to quickly automate enumeration for post-exploitation, and to learn C++ BOF dev using the newer Visual Studio  [Cobalt Strike templates](https://github.com/Cobalt-Strike/bof-vs).<br />

The BOF will only print out any files/folders found during enumeration and otherwise be silent. It also requires the `%APPDATA%`, `%LOCALAPPDATA%`, and `%WINDIR%` environment variables for file enumeration.<br />

## Commands Usage
This BOF contains the following commands:

|Command|Decription|
|----|----------|
|`enumfiles show`| Dont run checks, just show all enumeration checks and files/folders supported. |
|`enumfiles all` | Run all enumeration checks. |
|`enumfiles lolbins` | Run only lolbins checks. |
|`enumfiles remoting` | Run only remoting checks. |
|`enumfiles dotnet` | Run only dotnet checks. |
|`enumfiles browser-installs` | Run only browser installs checks. |
|`enumfiles browser-userdata` | Run only browser user data checks. |
|`enumfiles webservers` | Run only webserver checks. |
|`enumfiles powershell-hist` | Run only PowerShell history checks. |
|`enumfiles python` | Run only Python checks. |
|`enumfiles unattended` | Run only unattended file checks. |
