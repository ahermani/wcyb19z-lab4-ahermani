# Sprawozdanie z laboratorium nr 4

# Agnieszka Hermaniuk, nr albumu 303701, e-mail: 01149363@pw.edu.pl

# Zadanie 1

Do realizacji zadania zainstalowałam na VirtualBoxie wirualnego hosta Security Onion (https://github.com/Security-Onion-Solutions/security-onion/blob/master/Verify_ISO.md) oraz Windows 10 w ramach możliwości konta Azure for Students.

## Skonfigurować generowanie logów systemowych systemu Windows - Sysmon

Sysmona zainstalowałam, pobierając folder ze strony: https://github.com/SwiftOnSecurity/sysmon-config .
Następnie skonfigurowałam plik (`sysmonconfig-export.xml` - według tego tutoriala: [sysmon setup](https://www.youtube.com/watch?v=vqGoXQEK8pA)) i zainstalowałam Sysmona komendą:
```
sysmon.exe -accepteula -i sysmonconfig-export.xml
```

Sysmon automatycznie gromadzi logi, które można zaobserwować, przeglądać i filtrować, wchodząc w: 

Podgląd zdarzeń->Dzienniki aplikacji i usług->Microsoft->Windows->Sysmon->Operational

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/event_log.PNG)

Zgromadzone logi zapisałam do pliku komendą, aby mieć później możliwość wyeksportowania go do narzędzia Sysmon View:
```
WEVTUtil query-events "Microsoft-Windows-Sysmon/Operational" /format:xml /e:sysmonview > C:\Users\01149363\Desktop\Sysmon\eventlog.xml
```

Widok pliku:

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/sysmon_file.PNG)

Zapisany plik mogłam otworzyć w Sysmon View, który umożliwia lepszą wizualizację, a tym samym analizę logów, posiadając takie opcje jak: korelowanie i grupowanie zebranych logów na podstawie ich nazw, identyfikatorów GUID czy czasu powstania wydarzeń, zbudowanie drzewka hierarchii, czy też przedstawianie wyników na mapie na podstawie geolokalizacji adresów IP (bardziej czasochłonna opcja).

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/all_events_log.PNG)

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/event_hierarchy.PNG)

## Skonfigurować wysyłanie logów sysmon do Security Onion.

W tym celu wykorzystałam program Winlogbeat. Pobrałam go ze strony: https://www.elastic.co/downloads/beats/winlogbeat . 

Zainstalowałam program, wpisując w PowerShellu komendę:
```
PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
```

Następnie edytowałam plik konfiguracyjny (`winlogbeat.yml`), w którym należało odpowiednio ustawić setup kibany oraz output dla wysyłanych logów. 
  
  * Kibana
  ```
  setupt.kibana:
  host: "https://192.168.10.108/app/kibana"
  ```
  * Logstash
  ```
  output.logstash:
  hosts: ["192.168.10.108:5044"]
  ```

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/setup_kibana.PNG)

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/output_logstash.PNG)

Sprawdziłam poprawność konfiguracji komendą: 
```
.\winlogbeat.exe test config -c .\winlogbeat.yml -e
```
Zwróciła ona `Config OK`, zatem można było przejść do uruchomienia usługi, co wykonałam komendą:
```
start-service winlogbeat 
```
Ze względu na blokowanie komunikacji między Security Onion a Windowsem:
* Wyłączyłam firewalla na Windows (w ustawieniach)
* Wyłączyłam firewalla na Security Onion (komenda: `sudo ufw disable`

## Zaobserowować działanie za pomocą UI dostępnego w Security Onion - Kibana

Do Kibany przesłane zostały logi z Sysmona, co można było zauważyć już w zakładce `Dashboard`.

W zakładce Discover znajdują się zestawienie i szczegóły dotyczące tych logów. 

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/win_kibana.PNG)

## Przeanalizować zawartość informacyjną logów sysmon pod kątem wykrywania zagrożeń w cyberprzestrzeni

W Discover można odpowiednio filtrować dane według różnych pól, osi czasu itp. Po rozwinięciu szczegółów logów można sprawdzić takie informacje, jak: czas logów, nazwę hosta i jego system operacyjny, nazwę i ID eventu, jego rodzaj (np. informacyjny) itd. Znaczna większość zebranych u mnoie danych dotyczy `event ID 10`, czyli `Process accessed`, czyli gdy jakiś proces otwiera nowy proces. Warto w tym wypadku sprawdzić `SourceImage` oraz `TargetImage`. Zagrożeniem może być najczęściej, gdy zobaczymy, że uruchomiany był przez PowerShella Lsass.exe, co może być dokonane w celu kradzieży poświadczeń do ataktu Pass-the-Hash. Sytuacja taka może wyglądać np. gdy targetem jest lsass.exe, a sourcem mimikatz. W moim wypadku proces ten zawsze uruchamiany był z systemowego pliku svchost.exe.



# Zadanie 2

## W ramach możliwości konta Azure for Students ustanowić darmową maszynę wirtualną z systemem operacyjnym Linux

W ramach możliwości konta Azure for Students utworzyłam maszynę wirtualną z systemem Linux Ubuntu 16.04.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/create_vm.PNG)

Na etapie tworzenia maszyny jest możliwość (na dodatek zalecana przez witrynę) ustawienia opcji logowania przy użyciu nie hasła, a klucza SSH.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/log_with_ssh.PNG)

Następnie zalogowałam się do maszyny za pośrednictwem protokołu SSH.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/login.PNG)

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/login_successfull.PNG)

## Skonfigurować reguły firewalla

### Dopuścić ruch na porcie 80 oraz 443 (HTTP) z dowolnej maszyny

Wyświetliłam bieżący status firewalla komendą `iptables -S`

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/iptables_s.PNG)

Następnie dołączyłam odpowiednie reguły na końcu łańcucha. W celu dopuszczenia ruchu na portach wpisuje się komendę:
```
sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
```

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/80_443.PNG)

Sprawdziłam aktualnie akceptowane porty poleceniem `sudo iptables -L -n`

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/current_80_443.PNG)

### Dopuścić ruch dla usługi SSH tylko ze swojej maszyny

Dopuszczenie ruchu SSH tylko dla mojej maszyny wykonałam analogicznie do poprzedniej części zadania, z uwzględnieniem portu usługi SSH (`port 22`) oraz adresu IP źródła (`137.116.212.236`).
Użyłam więc komendy:
```
sudo iptables -A INPUT -p tcp -s 137.116.212.236 -m tcp --dport 22 -j ACCEPT
```
I ponownie wyświetliłam bieżący łańcuch firewalla.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/allow_only_ssh.PNG)

### Zablokować wszystkie nieużywane porty

Żeby zablokować wszystkie nieużywane porty (czyli pozostałe porty), należy użyć komendy zmieniającej defaultowe ustawienia firewalla:
```
sudo iptables -P INPUT DROP
```

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/drop_unused.PNG)

### Dopuścić ruch dla protokołu MQTT

MQTT to protokół transmisji danych, umożliwiający komunikację pomiędzy systemami za pomocą serwera pośredniczącego. Broker domyślnie słucha na porcie 1883

```
sudo iptables -A INPUT -p tcp -m tcp --dport 1883 -j ACCEPT
sudo iptables -A INPUT -p tcp -m tcp --dport 8883 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --dport 1883 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m tcp --dport 8883 -j ACCEPT
```

## Best Practices hardeningu systemu
Przykłady:
* silne loginy i hasła (minimum 8 znaków, w tym duże znaki i znaki specjalne)
* używanie niestandardowego portu dla SSH (zamiast 22)
* zablokowanie nieużywanych portów
* używanie klucza SSH do autoryzacji
* zmniejszenie liczby użytkowników, którzy mają możliwy zdalny dostęp
* dezaktywowanie logowania na roota przez SSH
* zablokowanie możliwości wysyłania flag i pingowania
* zablokowanie prób bruteforcowania haseł do SSH (przez Fail2Ban)
* ustawienie automatycznego zakończenia sesji po odpowiednim czasie braku aktywności
* dozwolenie dostępu do SSH tylko dla określonego adresu IP
* regularne aktualizacje

### SSH certificates logins
Użyłam następującej komendy do stworzenia pary kluczy SSH przy użyciu szyfrowania RSA i długości bitowej 4096:
```
ssh-keygen -m PEM -t rsa -b 4096
```
Klucze te domyślnie przechowywane są w katalogu ~/.ssh. Dodatkowo możemy (opcjonalnie) utowrzyć hasło dla klucza publicznego.

Następnie wyświetliłam klucz poleceniem:
```
cat ~/.ssh/id_rsa.pub
```
Klucz podałam na etapie tworzenia maszyny wirtualnej i od początku logowałam się przy jego użyciu. Można jednak przejść z logowania hasłem na logowanie przy użyciu kluczy SSH podczas użytkowania stworzonej już maszyny. Po utworzeniu klucza należy zmienić rodzaj uwierzytelnienia w pliku `sshd_config`.
```
sudo nano /etc/ssh/sshd_config
```

Ustawić `PasswordAuthentication` na `no`:

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/no_password.PNG)

Upewnić się, że `PubkeyAuthentication` ustawione jest na `yes`:

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/pub_key_auth.PNG)

Następnie używamy polecenia:
```
sudo service ssh restart
```

### Fail2Ban
Fail2Ban to program, który działa w tle, analizuje logi wybranych aplikacji, i na podstawie zdefiniowanych reguł szuka „złych zachowań” (np. nieudana próba logowania, brute force) i, jeśli natrafi na takie działania, to podejmuje akcje – blokuje.

Instalujemy go komendą: `sudo apt-get install fail2ban`.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/fail2ban_install.PNG)

Następnie kopiujemy podstawowy plik konfiguracyjny pod nową nazwą (w ten sposób unikamy możliwości nadpisania pliku z naszymi preferencjami np. po aktualizacji).
```
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```
Teraz należy skonfigurować plik w edytorze

```
sudo nano /etc/fail2ban/jail.local
```

Głównymi opcjami, na które należałoby zwrócić uwagę w podstawowej konfiguracji są:

* ignoreip - adresy, które wyłączone są z zasad fail2ban (domyślnie podany jest tutaj localhost)

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/ignore_ip.PNG)

* bantime - określa jak długo (w sekundach) ban będzie aktywny

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/bantime.PNG)

* maxretry - domyślna ilość prób połączenia, zanim ban zostanie nałożony na adres IP

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/maxretry.PNG)

Warto też przejść do sekcji `JAILS` i zmienić domyślny port usługi SSH.

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/change_ssh.PNG)

Po zapisaniu zmian w pliku zrestartowałam fail2ban komendą `sudo systemctl restart fail2ban`.

Teraz należało zablokować nieużywany już port 22, wpisując komendy:
```
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 22 -j DROP
```

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/fail2ban_iptables.PNG)

### Debsums
Debsums to narzędzie pozwalające zweryfikować spójność zainstalowanych plików pakietów, pod względem sum kontrolnych dostarczonych przez pakiet lub wygenerowanych z archiwum .deb. Dzięki niemu możemy stwierdzić, czy pliki na naszym dysku zostały zmodyfikowane, co raczej ciężko jest badać własnoręcznie.

Zainstalowałam narzędzie komendą: `sudo apt-get install debsums`. 

Użycie programu jest dość proste, komenda: `sudo debsums` analizuje wszystkie zainstalowane pakiety (bez plików konfiguracyjnych). Sprawdzenie tych plików możemy jednak wymusić, dopisując `-a`, z kolei opcja `-s` zwraca nam tylko wyniki z błędami, a `-c` tylko zmienione pliki.

W moim przypadku komendy wywołujące dwie ostatnie opcje nie zwróciły nic.

Fragment wyniku komendy `sudo debsums`:

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/sudo_debsums.PNG)

### Blokowanie pakietów z flagami
Wysyłanie pakietów z falgami SYN, XMAS i NULL to częste ataki przeprowadzane w celu wykrycia owtartych portów, udostępnianych usług, systemu operacyjnego. Pomaga też atakującym w rozpoznaniu topologii sieci lub zablokowaniu usług serwera. Dlatego ważna jest obrona przed nimi.
Polega na zablokowaniu możliwości wysyłania tych pakietów, czy też np. ustawieniu limitu na przesyłanie pakietów ICMP.
Użyłam następujących komend dopisujących reguły do firewalla:
* `sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP` - zablokowanie pakietów SYN
* `sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP` - zablokowanie pakietów z flagą XMAS
* `sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP` - zablokowanie pakietów z flagą NULL
* `sudo iptables -A INPUT -p icmp -m limit --limit 2/second --limit-burst 2 -j ACCEPT` - limit ICMP

![image](https://github.com/wcyb19z-lab/wcyb19z-lab4-ahermani/blob/screenshots/block_packets.PNG)

