@echo off
title Wiz Login
echo ============================================================
echo  Wiz API Login (IdP / SSO)
echo ============================================================
echo.
echo  1. Edge will open and take you to the Wiz login page.
echo  2. Sign in via your organization's IdP / SSO (+ MFA if prompted).
echo  3. Wait for the Wiz DASHBOARD to fully load.
echo  4. Come back here and press ENTER.
echo.
REM If 'python' opens the Microsoft Store or errors "Python was not found",
REM replace 'python' with 'py' (the Windows Python launcher) on the next line.
python "%~dp0wiz_fetch.py" login
echo.
if %ERRORLEVEL% EQU 0 (
    echo  Login successful! You can close this window.
) else (
    echo  Login failed. Check the error above and try again.
)
echo.
pause
