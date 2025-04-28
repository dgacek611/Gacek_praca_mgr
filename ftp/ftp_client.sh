#!/bin/bash

if [ -z "$1" ]; then
    echo "Użycie: $0 <czas_w_sekundach>"
    exit 1
fi

END_TIME=$((SECONDS + $1))  # Czas działania w sekundach podany jako argument

# Ustawienie katalogu domowego
DEST_DIR=~/destination_dir
mkdir -p $DEST_DIR  # Utwórz katalog, jeśli nie istnieje

echo "Rozpoczynam pobieranie plików z serwera FTP..."
echo "Pliki będą zapisane w katalogu: $DEST_DIR"

while [ $SECONDS -lt $END_TIME ]; do
    echo "Łączę się z serwerem FTP i pobieram pliki..."
    ftp -n 10.0.0.1 <<END_SCRIPT
    lcd $DEST_DIR
    user anonymous 123
    get file_10MB.log
    get file_25MB.log
    get file_100MB.log
    get file_775MB.log
    bye
END_SCRIPT
    echo "Zakończono pobieranie w tej iteracji. Oczekiwanie na kolejne..."
    sleep 1
done

echo "Zakończono pobieranie wszystkich plików po $1 sekundach."
echo "Pliki zapisane w $DEST_DIR."
