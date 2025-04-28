![{F3064DC3-56B9-44C6-8719-BA0B0D3A3447}](https://github.com/user-attachments/assets/689fc418-227f-4204-ba52-5b88c7bd56f4)# SDN_project
Temat projektu:
Implementacja QoS dla transmisji strumieniowej wideo w architekturze SDN z wykorzystaniem sterownika Faucet.

![topologia](https://github.com/user-attachments/assets/d529f1a0-4b10-4538-9199-ee0d1babfc4c)
     
Algorytm działania projektu

![473729032_637964905262114_6168636170125602289_n](https://github.com/user-attachments/assets/4fc753f9-9d99-4a2d-9ded-6566ccb18193)

Uruchomienie projektu:

1.Uruchom topologię mininet z wykorzystaniem komendy:

	$ sudo -E mn --custom project_topo_3_switches.py --topo mytopo --   controller=remote,ip=127.0.0.1,port=6653

2.Upewnij się że wszystkie pliki znajdujące się w /etc/faucet są odpowiednio skonfigurowane

2.1. W szczególności upewnij się że plik faucet.yaml zawiera konfigurację znajdującą się w pliku faucet_brak_ruchu.yaml

2.2. W pliku prometheus.yaml zmienne scrape_interval oraz evaluation_interval są ustawione na wartość 5s oraz jest ustawione monitorowanie:

     $   - job_name: 'faucet'
     $     static_configs:
     $       - targets: ['localhost:9302']
     $   - job_name: 'gauge'
     $     static_configs:
     $       - targets: ['localhost:9303']

2.3. W pliku ryu.conf są ustawione odpowiednie ścieżki do plików konfiguracyjnych:

     $ faucet_config = /etc/faucet/faucet.yaml
     $ gauge_config = /etc/faucet/gauge.yaml

3.Dodaj do pliku /etc/default/faucet zmienną środowiskową umożliwiającą automatyczne przeładowywanie sterownika gdy plik faucet.yaml ulegnie zmianie:

     $ FAUCET_CONFIG_STAT_RELOAD=1
     
4. Uruchom create_file_to_send_ftp.py oraz create_file_to_send_video.py
5. Przed uruchomieniem skryptu “faucet_modify_traffic.py” wykonaj poniższe komendy aby połączyć switch'e z gaugem, który będzie pobierał z nich dane o ruchu:
```
     $  sudo ovs-vsctl set-controller s1 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654
     $  sudo ovs-vsctl set-controller s2 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654
     $  sudo ovs-vsctl set-controller s3 tcp:127.0.0.1:6653 tcp:127.0.0.1:6654
```
6. Uruchom skrypt  faucet_modify_traffic.py
7. Uruchom po dwie instancje h1 oraz h2 komendą w mininecie : „xterm h1” oraz „xterm h2”
8. Generatory ruchu:

8.1. Ruch FTP

8.1.1. Instalacja vsftp na ubuntu

     $ sudo apt install vsftpd

8.1.2. Edycja pliku konfiguracyjnego vsftpd

     $ sudo nano /etc/vsftpd.conf

Restart serwera FTP, aby zastosować zmiany

     $ sudo systemctl restart vsftpd

8.1.3. Na hoście h1 uruchomienie serwera FTP

     $ /usr/sbin/vsftpd /etc/vsftpd.conf

8.1.4. Na hoście h2 uruchomienie skryptu generującego ruch

     $ ./ftp_client.sh <duration>

8.2. Ruch video

8.2.1. Instalacja vlc

     $ sudo apt install vlc -y

8.2.2. Uruchomienie serwera 

     $ vlc-wrapper -I dummy udp://@:1234

8.2.3. Uruchomienie klienta 

     $ vlc-wrapper -I dummy -vvv /data/video_100MB.mp4 --sout "#standard{access=udp,mux=ts,dst=10.0.0.2:1234}" --sout-x264-keyint=10 --loop

9.Aby zaobserwować zmiany ścieżki można skorzystać z komend:

     $ sudo tcpdump -i s2-eth1 -n
     $ sudo tcpdump -i s2-eth3 -n
	
