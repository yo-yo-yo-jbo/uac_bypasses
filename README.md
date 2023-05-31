# A bit about UAC bypasses
Today I wanted to talk a bit about UAC bypasses.  
In this blogpost I will describe what UAC is, how to approach UAC bypass hunting and what the future might hold.

## Motivation for UAC
`User Account Control` (or `UAC` for short) is an security enforcement feature introduced in Windows Vista.  
In the Windows ecosystem, most users run as a local administrator, which is problematic; the security boundary between non-administrator and administrator in Windows is clear, but there is no clear boundary between administrator and running as the `SYSTEM` user (can be easily be done with a `Windows Service`, for example). Today we have other boundaries such as `Protected Processes` and the kernel (enforced with `DSE`) not to mention hypervison technology, but the boundary between administrator and non-administrator is pointless in a world where everyone runs as a local admin.  
To address the problem, Microsoft introduced `UAC`, which splits the administrator token into two parts: one has restricted privileges (similar to a non-administrator user) and one has elevated privileges. When a privileged operation is about to happen, a user must consent to the operation, and then the elevated token could be used. This procedure is known as `elevation`.  
This was not perceived well - Windows Vista is known to be full of UAC-style consent popups. To address that, several measures had to be taken:
- UAC has 4 different levels, ranging between not enforcing at all to "full UAC" (which is what happened during the Vista days). The default mode is somewhere "in-between"; most UAC bypasses focus this level.

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
- An empty `SACL` is interpreted a `Medium integrity level`.

