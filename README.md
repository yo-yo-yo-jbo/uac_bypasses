# A bit about UAC bypasses
Today I wanted to talk a bit about UAC bypasses.  
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

Usually UAC bypasses are logic bugs that let an attacker affect an auto-elevated program's operation or flow in a way that ultimately executes arbitrary code. I'd like to share a few examples I discovered in the past:

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

## HKCU and HKCR
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
