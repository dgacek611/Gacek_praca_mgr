import subprocess
import os

def generate_video(output_file, target_size_mb):
    # Tymczasowy plik wideo
    temp_file = "temp_video.mp4"
    duration = 30  # Czas trwania wideo w sekundach
    bitrate_kbps = ((target_size_mb * 1024 * 1024) * 8) // (duration * 1000)

    # Generowanie wideo za pomoca ffmpeg
    command = [
        "ffmpeg",
        "-y",  # Nadpisz istniejacy plik
        "-f", "lavfi",  # Zrodlo: obraz testowy
        "-i", "testsrc=size=1280x720:rate=30",
        "-f", "lavfi",  # Zrodlo: dzwiek testowy
        "-i", "sine=frequency=440",
        "-c:v", "libx264",
        "-b:v", f"{bitrate_kbps}k",
        "-t", str(duration),  # Dlugosc wideo
        temp_file
    ]
    print(f"Generuje tymczasowe wideo: {temp_file}")
    subprocess.run(command, check=True)

    # Wypelnianie pliku do zadanego rozmiaru
    target_size_bytes = target_size_mb * 1024 * 1024
    with open(temp_file, "rb") as f_in, open(output_file, "wb") as f_out:
        f_out.write(f_in.read())  # Skopiuj dane wideo
        current_size = f_out.tell()
        if current_size < target_size_bytes:
            f_out.write(b'\x00' * (target_size_bytes - current_size))  # Wypelnij null bytes
    print(f"Plik {output_file} utworzony o rozmiarze {target_size_mb} MB")

    # Usun plik tymczasowy
    os.remove(temp_file)

# Sciezka wyjsciowa
output_folder = "/data"
os.makedirs(output_folder, exist_ok=True)

# Lista rozmiarow w MB i odpowiednich nazw plikow
sizes_and_files = [
    (100, "video_100MB.mp4"),
    (250, "video_250MB.mp4"),
    (1000, "video_1000MB.mp4"),
]

# Generowanie wideo
for size, file_name in sizes_and_files:
    output_path = os.path.join(output_folder, file_name)
    generate_video(output_path, size)

print("Wszystkie pliki wideo zostaly wygenerowane.")
