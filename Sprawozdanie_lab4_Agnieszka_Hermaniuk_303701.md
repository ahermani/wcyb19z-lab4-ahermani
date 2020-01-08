# Sprawozdanie z laboratorium nr 4

# Agnieszka Hermaniuk, nr albumu 303701, e-mail: 01149363@pw.edu.pl

# Zadanie 1
## Instalacja i konfiguracja Sysmona

Sysmona zainstalowałam, pobierając folder ze strony: https://github.com/SwiftOnSecurity/sysmon-config
Następnie skonfigurowałam plik i zainstalowałam Sysmona komendą:
```
sysmon.exe -accepteula -i sysmonconfig-export.xml
```

Sysmon automatycznie gromadzi logi, które można zaobserwować i przeglądać, wchodząc w: 
Podgląd zdarzeń->Dzienniki aplikacji i usług->Microsoft->Windows->Sysmon->Operational

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/event_log.PNG)

Zgromadzone logi zapisałam do pliku komendą:
```
WEVTUtil query-events "Microsoft-Windows-Sysmon/Operational" /format:xml /e:sysmonview > C:\Users\01149363\Desktop\Sysmon\eventlog.xml
```

Widok pliku:

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/sysmon_file.PNG)

Zapisany plik mogłam otworzyć w narzędziu Sysmon View, które umożliwia lepszą wizualizację, a tym samym analizę logów, posiadając takie opcje jak: korelowanie i grupowanie zebranych logów, zbudowanie drzewka hierarchii, czy też przedstawianie wyników na mapie na podstawie geolokalizacji adresów IP.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/all_events_log.PNG)

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/event_hierarchy.PNG)

## Wysyłanie logów z Sysmona do Security Onion

W tym celu wykorzystałam Winlogbeata. Pobrałam go ze strony: https://www.elastic.co/downloads/beats/winlogbeat . Następnie edytowałam plik konfiguracyjny. Ustawiłam setup Kibany oraz output: Logstash.

![image]()

Sprawdziłam poprawność konfiguracji komendą: 
```
.\winlogbeat.exe test config -c .\winlogbeat.yml -e
```
I uruchomiłam usługę:
```
start-service winlogbeat 
```
Do Kibany przesłane zostały logi z Sysmona, które pojawiły się na Dashboardzie.

W zakładce Discover znajduje się zestawienie i szczegóły dotyczące tych logów. Znaczna większość dotyczny `event ID 10`, czyli `Process accessed`. 
