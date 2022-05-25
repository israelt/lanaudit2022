# Lanzador de NMAP para LANAudit
# Israel Torres Gonzalo
# Update 2022 Q2 - Master Ciberseguridad TSS 

from shlex import split
import subprocess


def portscan(hosts, ports='', arguments='', logname='cnmap'):
    # Se formatean correctamente los argumentos
    if ports == '':
        ports = ' '
    else:
        ports = ' -p' + ports + ' '

    logname = ' -oA ' + logname + ' '

    # Se prepara la cadena de comandos a ejecutar
    commandraw = ('sudo /usr/bin/nmap' + ports + hosts + logname + arguments)
    command = split(commandraw)
    p = subprocess.Popen(command, bufsize=100000,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    var = p.stdout.read()
