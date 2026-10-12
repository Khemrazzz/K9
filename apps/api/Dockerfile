# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:10.0.401-alpine3.23 AS build
WORKDIR /src
COPY global.json Directory.Build.props ./
COPY K9.Api/K9.Api.csproj K9.Api/packages.lock.json K9.Api/
RUN dotnet restore K9.Api/K9.Api.csproj --locked-mode
COPY K9.Api/ K9.Api/
RUN dotnet publish K9.Api/K9.Api.csproj -c Release -o /app --no-restore

# Chiseled: no shell or package manager, runs as a non-root user, listens on 8080.
FROM mcr.microsoft.com/dotnet/aspnet:10.0.12-noble-chiseled
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "K9.Api.dll"]
