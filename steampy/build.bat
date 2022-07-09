SET CC=C:\mingw64\bin\gcc.exe
REM call nuitka --remove-output --module --no-pyi-file --recurse-none client.py
REM call nuitka --remove-output --module --no-pyi-file --recurse-none confirmation.py
REM call nuitka --remove-output --module --no-pyi-file --recurse-none guard.py
REM call nuitka --remove-output --module --no-pyi-file --recurse-none login.py
call nuitka --remove-output --module --no-pyi-file --recurse-none utils.py
DEL /F *.lib *.exp *.a