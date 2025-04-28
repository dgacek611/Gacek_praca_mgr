import os

# Sciezka do folderu, w ktorym maja byc tworzone pliki
data_folder = "/data"

# Sprawdzenie, czy folder istnieje, jesli nie, to go utworz
if not os.path.exists(data_folder):
    os.makedirs(data_folder)
    print(f"Folder '{data_folder}' zostal utworzony.")
else:
    print(f"Folder '{data_folder}' juz istnieje.")

# Rozmiary plikow w megabajtach
file_sizes_mb = [10, 25, 100, 775]

# Tworzenie plikow o okreslonych rozmiarach
file_paths = []
for size_mb in file_sizes_mb:
    file_path = os.path.join(data_folder, f"file_{size_mb}MB.log")
    with open(file_path, 'wb') as f:
        f.write(b'\0' * size_mb * 1024 * 1024)  # Tworzenie pliku o okreslonym rozmiarze
    print(f"Plik '{file_path}' zostal utworzony o rozmiarze {size_mb} MB.")
    file_paths.append(file_path)

print("Utworzone pliki:", file_paths)