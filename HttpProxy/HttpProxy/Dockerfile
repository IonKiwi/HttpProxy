#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0.1-alpine3.14-amd64 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/sdk:6.0.101-alpine3.14-amd64 AS build
WORKDIR /src
COPY ["HttpProxy/HttpProxy.csproj", "HttpProxy/"]
RUN dotnet restore "HttpProxy/HttpProxy.csproj"
COPY . .
WORKDIR "/src/HttpProxy"
RUN dotnet build "HttpProxy.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "HttpProxy.csproj" -c Release -o /app/publish
RUN find /app/publish -type d -exec chmod 0755 {} \;
RUN find /app/publish -type f -exec chmod 0644 {} \;

FROM base AS final
RUN apk add --no-cache icu-libs; apk add tzdata; cp /usr/share/zoneinfo/CET /etc/localtime;
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT false
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "HttpProxy.dll"]