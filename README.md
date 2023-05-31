# A bit about UAC bypasses
Today I wanted to talk a bit about UAC bypasses.  
In this blogpost I will describe what UAC is, how to approach UAC bypass hunting and what the future might hold.

## What is UAC
`User Account Control` (or `UAC` for short) is an security enforcement feature introduced in Windows Vista.  
In the Windows ecosystem, most users run as a local administrator, which is problematic; the security boundary between non-administrator and administrator in Windows is clear, but there is no clear boundary between administrator and running as the `SYSTEM` user (can be easily be done with a `Windows Service`, for example). Today we have other boundaries such as `Protected Processes` and the kernel (enforced with `DSE`) not to mention hypervison technology, but the boundary between administrator and non-administrator is pointless in a world where everyone runs as a local admin.  
To address the problem, Microsoft introduced `UAC`, which splits the administrator token into two parts: one has restricted privileges (similar to a non-administrator user) and one has elevated privileges. When a privileged operation is about to happen, a user must consent to the operation, and then the elevated token could be used. This procedure is known as `elevation`.  
This was not perceived well - Windows Vista is known to be full of UAC-style consent popups. To address that, several measures had to be taken:
- UAC has 4 different levels, ranging between not enforcing at all to "full UAC" (which is what happened during the Vista days). The default mode is somewhere "in-between"; most UAC bypasses focus this level.
