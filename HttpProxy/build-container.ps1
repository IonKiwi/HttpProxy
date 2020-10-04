# & docker build -f ".\HttpProxy\Dockerfile" --force-rm -t httpproxy "."
# & docker build -f ".\HttpProxy\Dockerfile.Windows" --force-rm -t httpproxy "."
& 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe' .\HttpProxy\HttpProxy.csproj /t:ContainerBuild /p:Configuration=Release
