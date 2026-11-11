
import subprocess
import json
import os
from datetime import datetime

def ejecutar_powershell(comando):
    resultado = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-Command", comando],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=3600
    )
    if resultado.returncode != 0:
        raise RuntimeError(resultado.stderr.strip() or "Error de Windows")
    return resultado.stdout.strip()

def escaneo_rapido():
    print("Iniciando escaneo real con Microsoft Defender...")
    ejecutar_powershell("Start-MpScan -ScanType QuickScan")
    print("Escaneo finalizado. Consulta el historial de detecciones.")

def estado_proteccion():
    print("Consultando Microsoft Defender...")
    datos = ejecutar_powershell(
        "Get-MpComputerStatus | "
        "Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
        "AntivirusSignatureLastUpdated | ConvertTo-Json"
    )
    print(datos)

def amenazas_detectadas():
    print("Historial de amenazas:")
    datos = ejecutar_powershell(
        "Get-MpThreatDetection | "
        "Select-Object ThreatID,InitialDetectionTime,"
        "ActionSuccess,Resources | ConvertTo-Json -Depth 4"
    )
    print(datos if datos else "No hay detecciones registradas.")

def menu():
    while True:
        print("\n===== CLEANER ANTI-RAT =====")
        print("1. Escaneo antivirus rapido")
        print("2. Estado de proteccion")
        print("3. Historial de amenazas")
        print("4. Salir")

        opcion = input("Selecciona una opcion: ")

        try:
            if opcion == "1":
                escaneo_rapido()
            elif opcion == "2":
                estado_proteccion()
            elif opcion == "3":
                amenazas_detectadas()
            elif opcion == "4":
                break
            else:
                print("Opcion no valida")
        except Exception as error:
            print("Error:", error)

if __name__ == "__main__":
    menu()
