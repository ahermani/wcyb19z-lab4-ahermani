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

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/setup_kibana.PNG)

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/output_logstash.PNG)

Sprawdziłam poprawność konfiguracji komendą: 
```
.\winlogbeat.exe test config -c .\winlogbeat.yml -e
```
I uruchomiłam usługę:
```
start-service winlogbeat 
```
Do Kibany przesłane zostały logi z Sysmona, które pojawiły się na Dashboardzie.

W zakładce Discover znajduje się zestawienie i szczegóły dotyczące tych logów. Po rozwinięciu można sprawdzić takie cechy, jak:...Znaczna większość dotyczy `event ID 10`, czyli `Process accessed`, czyli gdy jakiś proces otwiera nowy proces. Warto w tym wypadku sprawdzić `SourceImage` oraz `TargetImage`. Zagrożeniem może być najczęściej, gdy zobaczymy, że uruchomiany był przez PowerShella Lsass.exe, co może być dokonane w celu kradzieży poświadczeń do ataktu Pass-the-Hash. Sytuacja taka może wyglądać np. gdy targetem jest lsass.exe, a sourcem mimikatz. W moim wypadku proces ten zawsze uruchamiany był z systemowego pliku svchost.exe.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/win_kibana.PNG)

# Zadanie 2

## Utworzenie maszyny wirtualnej

W ramach możliwości konta Azure for Students utworzyłam maszynę wirtualną z systemem Linux Ubuntu 16.04.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/create_vm.PNG)

Na etapie tworzenia maszyny jest możliwość ustawienia opcji logowania przy użyciu klucza SSH.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/log_with_ssh.PNG)

Następnie zalogowałam się do maszyny za pośrednictwem protokołu SSH.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/login.PNG)

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/login_successfull.PNG)

## Firewall

Wyświetliłam bieżący łańcuch firewalla komendą `iptables -S`

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/iptables_s.PNG)

Następnie dołączyłam odpowiednie reguły na końcu łańcucha. W celu dopuszczenia ruchu na portach wpisuje się komendę:
```
sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
```

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/80_443.PNG)

Sprawdziłam aktualnie akceptowane porty poleceniem `sudo iptables -L -n`

![image]()


Dopuszczenie ruchu SSH tylko dla mojej maszyny wykonałam analogicznie, do poprzedniej części zadania, z uwzględnieniem portu usługi SSH (`port 22`) oraz source adresu IP (`168.62.40.165`).
Użyłam więc komendy:
```
sudo iptables -A INPUT -p tcp -s 168.62.40.165 -m tcp --dport 22 -j ACCEPT
```
I ponownie wyświetliłam bieżący łańcuch firewalla.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/allow_SSH.PNG)

Żwby zablokować wszystkie nieużywane porty (czyli pozostałe porty), należy użyć komend:
```
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
```
