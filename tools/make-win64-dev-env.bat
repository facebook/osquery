@echo off
REM Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass .\tools\provision.ps1
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%
%ALLUSERSPROFILE%\chocolatey\bin\refreshenv.cmd
