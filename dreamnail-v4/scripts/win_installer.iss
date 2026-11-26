; Weather (Dreamnail v4) — Windows installer (Inno Setup).
;
; v4 has NO PyInstaller launcher: the app is the Flutter Release folder itself
; (dreamnail_ui.exe + the Flutter DLLs + the native engine dreamnail_ffi.dll +
; the sibling xray.exe + data\). This installs that whole folder to Program
; Files, adds Start Menu + optional desktop shortcuts, and best-effort whitelists
; the app in Windows Defender at install time (an installer already has the admin
; rights Add-MpPreference needs).
;
; Built in CI by build-v4.yml, which passes paths + version as /D defines.

#ifndef MyVersion
  #define MyVersion "0.0.0"
#endif
#ifndef MyOutputBase
  #define MyOutputBase "Weather-Installer"
#endif
#ifndef MyOutputDir
  #define MyOutputDir "out"
#endif
#ifndef MySourceDir
  #define MySourceDir "release"
#endif

[Setup]
; Stable AppId (distinct from v2's) so v4 upgrades replace cleanly.
AppId={{D4A8F1C6-9B2E-4A73-8F1D-3C5E7A9B0D24}
AppName=Weather
AppVersion={#MyVersion}
AppPublisher=Weather
DefaultDirName={autopf}\Weather
DefaultGroupName=Weather
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\dreamnail_ui.exe
UninstallDisplayName=Weather
OutputDir={#MyOutputDir}
OutputBaseFilename={#MyOutputBase}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
; Field bug (6.5.2/6.5.3): an upgrade over a running copy failed. The app
; hides to the tray on close, the elevated stealth helper has no window, and
; xray.exe runs from {app}, so a "please close" was never obeyed and the locked
; files broke the install. Now the code section below force-stops everything
; first (plain taskkill/schtasks, no script file), the app quits for real on
; Restart Manager's shutdown message (windows/runner/flutter_window.cpp),
; Restart Manager is a forced backstop, and any file STILL locked is replaced
; at the next reboot (restartreplace) instead of failing the install.
CloseApplications=force
CloseApplicationsFilter=*.exe,*.dll
RestartApplications=no
#ifdef MyIcon
SetupIconFile={#MyIcon}
#endif

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[InstallDelete]
; Clear the previous build's Flutter assets so old and new files never mix.
Type: filesandordirs; Name: "{app}\data"

[Files]
; The entire Flutter Release folder (exe + flutter DLLs + dreamnail_ffi.dll +
; xray.exe + data\). restartreplace: a file still locked after the stop step is
; swapped at the next reboot rather than aborting; uninsrestartdelete: same for
; uninstall.
Source: "{#MySourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion restartreplace uninsrestartdelete

[Icons]
Name: "{group}\Weather"; Filename: "{app}\dreamnail_ui.exe"
Name: "{group}\Uninstall Weather"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Weather"; Filename: "{app}\dreamnail_ui.exe"; Tasks: desktopicon

[Run]
; Best-effort Defender allow: the install dir + the per-user data dir the engine
; writes (%APPDATA%\Dreamnail). SilentlyContinue so Tamper Protection / no
; Defender can't fail the install.
Filename: "powershell.exe"; Parameters: "-NoProfile -WindowStyle Hidden -Command ""Add-MpPreference -ExclusionPath '{app}','{userappdata}\Dreamnail' -ErrorAction SilentlyContinue"""; StatusMsg: "Configuring Windows Security..."; Flags: runhidden waituntilterminated
Filename: "{app}\dreamnail_ui.exe"; Description: "Launch Weather"; Flags: nowait postinstall skipifsilent
; Silent update (/RELAUNCH, passed by the app's updater / the self-relaunch in
; InitializeSetup): start the new version again. Via explorer.exe so it runs as
; the normal user, NOT elevated, even though this installer is.
Filename: "{win}\explorer.exe"; Parameters: """{app}\dreamnail_ui.exe"""; Flags: nowait; Check: RelaunchWanted

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -WindowStyle Hidden -Command ""Remove-MpPreference -ExclusionPath '{app}','{userappdata}\Dreamnail' -ErrorAction SilentlyContinue"""; Flags: runhidden; RunOnceId: "DelDefenderExcl"

[UninstallDelete]
; Everything Weather leaves behind (field bug 6.5.2: uninstall left data): the
; install folder (logs + files the app wrote itself) and the per-user data
; (saved login, settings, logs, Flutter app storage).
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{userappdata}\Dreamnail"
Type: filesandordirs; Name: "{localappdata}\Dreamnail"
Type: filesandordirs; Name: "{userappdata}\com.dreamnail"

[Code]
// Run a System32 tool hidden and wait. Plain executables only — no PowerShell
// script file (a hidden -ExecutionPolicy Bypass script from %TEMP% is exactly
// what antivirus / ASR rules block, which silently skipped the 6.5.3 kill).
procedure ExecHidden(const Exe, Params: String);
var
  Rc: Integer;
begin
  Exec(ExpandConstant('{sys}\') + Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Rc);
end;

// tasklist always exits 0, so pipe it through find (exit 0 only on a match).
function IsRunning(const Image: String): Boolean;
var
  Rc: Integer;
begin
  Result := Exec(ExpandConstant('{cmd}'),
    '/C tasklist /NH /FI "IMAGENAME eq ' + Image + '" | find /I "' + Image + '" >NUL',
    '', SW_HIDE, ewWaitUntilTerminated, Rc) and (Rc = 0);
end;

// Stop every Weather process so its files can be replaced (install) or deleted
// (uninstall). Order matters: stop the app FIRST — the stealth helper watches
// it and, once it's gone, unwinds cleanly (restores routes + DNS) — then give
// the helper a few seconds before force-stopping it. xray.exe is in a
// kill-on-close job owned by the app, so it goes with the app. Never /T (tree):
// the app may be this installer's parent (in-app update). Returns True when
// nothing is left running.
function StopWeather(DeleteTask: Boolean): Boolean;
var
  I: Integer;
begin
  ExecHidden('taskkill.exe', '/F /IM dreamnail_ui.exe');
  ExecHidden('taskkill.exe', '/F /IM dreamnail-backend.exe');
  // v2 (Weather.exe) used this same folder under a different AppId.
  ExecHidden('taskkill.exe', '/F /IM Weather.exe');
  for I := 1 to 16 do
  begin
    if not IsRunning('dreamnail-tunhelper.exe') then
      Break;
    Sleep(500);
  end;
  ExecHidden('taskkill.exe', '/F /IM dreamnail-tunhelper.exe');
  ExecHidden('schtasks.exe', '/End /TN DreamnailStealth');
  if DeleteTask then
    ExecHidden('schtasks.exe', '/Delete /TN DreamnailStealth /F');
  // Let Windows release the file handles before Setup touches {app}.
  Sleep(800);
  Result := not (IsRunning('dreamnail_ui.exe') or IsRunning('dreamnail-tunhelper.exe'));
end;

function RelaunchWanted(): Boolean;
begin
  Result := Pos('/RELAUNCH', UpperCase(GetCmdTail)) > 0;
end;

// Upgrade launched as a normal wizard — what OLDER apps (5.x–6.5.6) do when
// they update. Don't make the user click through it: skip every question page
// and press Finish automatically (the "Launch Weather" postinstall entry then
// restarts the app as the normal user). A fresh install keeps the wizard.
// (6.5.6 re-ran itself /SILENT instead; that hand-off hung under test, so no
// second process now.)
var
  AutoUpgrade: Boolean;

function InitializeSetup(): Boolean;
begin
  Result := True;
  AutoUpgrade := (not WizardSilent) and RegKeyExists(HKEY_LOCAL_MACHINE,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{D4A8F1C6-9B2E-4A73-8F1D-3C5E7A9B0D24}_is1');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := AutoUpgrade and ((PageID = wpWelcome) or (PageID = wpSelectDir) or
    (PageID = wpSelectProgramGroup) or (PageID = wpSelectTasks) or (PageID = wpReady));
end;

// Inno ALWAYS shows the Ready page when every page before it was skipped
// (seen in a Wine test of 6.5.7: the upgrade sat on "Ready to Install"), so
// press Install there too, then Finish at the end.
// Calling NextButton.OnClick from inside CurPageChanged is ignored (the page
// change is still in progress — 6.5.8 sat on Ready), so POST a click instead:
// it's handled right after the page has finished appearing.
const
  BM_CLICK = $00F5;

procedure CurPageChanged(CurPageID: Integer);
begin
  if AutoUpgrade and ((CurPageID = wpReady) or (CurPageID = wpFinished)) then
    PostMessage(WizardForm.NextButton.Handle, BM_CLICK, 0, 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  // Try twice; if something still won't die, carry on anyway — restartreplace
  // swaps any still-locked file at the next reboot instead of breaking the
  // install. The scheduled task ("remember admin") is kept on upgrade.
  if not StopWeather(False) then
    StopWeather(False);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    StopWeather(True);
end;
