@echo off
REM Run from the SKILL ROOT (the parent of scripts\), not from scripts\ itself, so
REM Output\snow_ticket_pending.json is found where the report workflow wrote it.
cd /d "%~dp0.."
REM If 'python' opens the Microsoft Store or errors "Python was not found",
REM replace 'python' with 'py' (the Windows Python launcher) on the next line.
python scripts\snow_ticket_creator.py
pause
