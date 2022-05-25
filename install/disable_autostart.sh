#!/bin/bash
# EJECUTAR CON PERMISOS DE ROOT / SUDO EN UNA DISTRIBUCION RECIEN INSTALADA
# PROBADO EN KALI2022.2
# DESINSTALANDO AUTOARRANQUE
sudo update-rc.d lanaudit-boot.sh remove
sudo rm /etc/init.d/lanaudit-boot.sh
