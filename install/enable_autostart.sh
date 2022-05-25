#!/bin/bash
# EJECUTAR CON PERMISOS DE ROOT / SUDO EN UNA DISTRIBUCION RECIEN INSTALADA
# PROBADO EN KALI2022.2
# INSTALANDO AUTOARRANQUE
sudo cp /opt/lanaudit/install/lanaudit-boot.sh /etc/init.d/
sudo chmod +x /etc/init.d/lanaudit-boot.sh
sudo update-rc.d lanaudit-boot.sh defaults
