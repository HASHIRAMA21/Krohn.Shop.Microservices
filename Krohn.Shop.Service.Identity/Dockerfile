FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["Krohn.Shop/Krohn.Shop.Service.Identity/Krohn.Shop.Service.Identity.csproj", "Krohn.Shop.Service.Identity/"]
RUN dotnet restore "Krohn.Shop.Service.Identity/Krohn.Shop.Service.Identity.csproj"
COPY . .
WORKDIR "/src/Krohn.Shop.Service.Identity"
RUN dotnet build "Krohn.Shop.Service.Identity.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Krohn.Shop.Service.Identity.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Krohn.Shop.Service.Identity.dll"]
