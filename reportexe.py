# Realiza el reporte ejecutivo
# Israel Torres Gonzalo
# Update 2022 Q2 - Master Ciberseguridad TSS 

import sqlite3
import os
from datetime import datetime

scriptdir = (os.path.dirname(os.path.realpath(__file__)))


def lastlines(file, lines=15):
    # Devuelve las últimas líneas de un fichero de texto
    BLOCK_SIZE = 1024
    file.seek(0, 2)
    block_end = file.tell()
    remaining = lines
    block_number = -1
    blocks = []
    while remaining > 0 and block_end > 0:
        if (block_end - BLOCK_SIZE > 0):
            file.seek(block_number * BLOCK_SIZE, 2)
            blocks.append(file.read(BLOCK_SIZE))
        else:
            file.seek(0, 0)
            blocks.append(file.read(block_end))
        done = blocks[-1].count(b'\n')
        remaining -= done
        block_end -= BLOCK_SIZE
        block_number -= 1
    output = b''.join(reversed(blocks))
    lastlines = b'\n'.join(output.splitlines()[-lines:])
    lastlines = str(lastlines)[2:]
    lastlines = lastlines.replace('\\n', '<br>').replace('\\t', '')
    return lastlines


def correctdate(mydate):
    # Formatea correctamente una fecha desde el timestamp creado en el proceso
    mynewdate = mydate[6:8] + '/' + mydate[4:6] + '/' + mydate[0:4] + ' a las ' + mydate[9:11] + ':' + mydate[11:13]
    return mynewdate


def tr_ipconfig(onlyname):
    # Encargado de generar la cabecera del reporte y la sección de Configuración inicial
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    date = correctdate(onlyname)
    now = datetime.now()
    nowdate = now.strftime("%d/%m/%Y a las %H:%M")
    # Se genera código HTML de reporte con los valores obtenidos desde SQLITE
    html_str = """\
    <html !DOCTYPE>
        <head>
            <title>LANAudit - Reporte ejecutivo</title>
            <link rel="stylesheet" href="./../style.css">
        </head>
        <body>
            <img src="./../lanaudit.png" alt="LANAudit Logo">
            <h1>REPORTE EJECUTIVO</h1>
            <p><b>Auditoría realizada el {date} (Inicio de la auditoría)</b></p>
            <p><b>Reporte realizado el {nowdate}</b></p>
            <br>
    """.format(date=date, nowdate=nowdate)
    html_file= open(htmlfile, "w")
    html_file.write(html_str)
    html_file.close()


def tr_nmap(onlyname):
    # Encargado de generar la sección de escaneo de hosts y puertos mediante NMAP
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se genera código HTML de reporte
    html_str = """\
            <h2>RESULTADO DEL ESCÁNER DE PUERTOS</h2>
            <p>
                En el escáner de puertos realizado con NMAP se han encontrado los siguientes puertos abiertos.<br>
                Se recomienda su revisión para cerrar o desactivar los servicios no necesarios.
            </p>
            <table>
                <tr>
                    <th>IP</th>
                    <th>Sistema Operativo</th>
                    <th>Protocolo</th>
                    <th>Puerto</th>
                    <th>Version</th>
                </tr>
    """
    html_file= open(htmlfile, "a")
    html_file.write(html_str)
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT ip, os, protocol, port, service, version from nmap")
    html_file = open(htmlfile, "a")
    while True:
        row = cursor.fetchone()
        if row is None:
            connection.close()
            break
        # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
        html_str = """\
                    <tr>
                        <td>{ip}</td>
                        <td>{os}</td>
                        <td>{protocol}</td>
                        <td>{port}</td>
                        <td>{version}</td>
                    </tr>
        """.format(ip=str(row[0]), os=str(row[1]), protocol=str(row[2]), port=str(row[3]) ,version=str(row[4]))
        html_file.write(html_str)
    html_str = """\
            </table>
            <br>
     """
    html_file.write(html_str)
    html_file.close()


def tr_dhcp(onlyname):
    # Encargado de generar la sección de vulnerabilidades DHCP
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM dhcp WHERE vunl = 'SI'")
    howmany = cursor.fetchone()
    # Si existe vulnerabilidad
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES DHCP</h2>
                <p>
                    El escáner ha detectado la red como <span style='color:red'>vulnerable</span> a ataques de agotamiento DHCP.<br>
                    Se recomienda su revisión y limitar la asignación de direcciónes IP mediante un filtrado de MAC. 
                </p>
                <br>
        """
        html_file= open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se consulta base de datos SQLITE
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES DHCP</h2>
                   <p>
                       El escáner ha detectado la red como <span style='color:green'>NO vulnerable</span> a ataques de agotamiento DHCP o no tiene IP libres para asignar.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)


def tr_netbios(onlyname):
    # Encargado de generar la sección de vulnerabilidades NETBIOS
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM netbios WHERE vunl = 'SI'")
    howmany = cursor.fetchone()
    # Si existe vulnerabilidad
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES NETBIOS</h2>
                <p>
                    El escáner ha detectado hosts <span style='color:red'>vulnerables</span> a ataques NETBIOS.<br>
                    Se recomienda su revisión para valorar la desactivación o limitación de los servicios NETBIOS en la red.<br>
                </p>
                <p>
                    Listado de hosts vulnerables a ataques NETBIOS:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                        <th>Fichero de registro disponible</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, output from netbios WHERE vunl = 'SI'")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                            <td>{output}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]), output=str(row[2]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES NETBIOS</h2>
                   <p>
                       El escáner ha detectado que los hosts de la red son <span style='color:green'>NO vulnerables</span> a ataques NETBIOS.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_smb(onlyname):
    # Encargado de generar la sección de vulnerabilidades SMB
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM smb WHERE vunl = 'SI'")
    howmany = cursor.fetchone()
    # Si existe vulnerabilidad
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES SMB</h2>
                <p>
                    El escáner ha detectado hosts <span style='color:red'>vulnerables</span> a ataques SMB.<br>
                    Se recomienda su revisión para valorar la desactivación, actualización o limitación de acceso a los servicios SMB en la red.<br>
                </p>
                <p>
                    Listado de hosts vulnerables a ataques SMB:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                        <th>Fichero de registro disponible</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, output from smb WHERE vunl = 'SI'")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                            <td>{output}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]), output=str(row[2]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES SMB</h2>
                   <p>
                       El escáner ha detectado que los hosts de la red son <span style='color:green'>NO vulnerables</span> a ataques SMB.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_smbghost(onlyname):
    # Encargado de generar la sección de vulnerabilidades SMB GHOST
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM smbghost WHERE vunl = 'SI'")
    howmany = cursor.fetchone()
    # Si existe vulnerabilidad
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES SMB GHOST</h2>
                <p>
                    El escáner ha detectado hosts <span style='color:red'>vulnerables</span> a ataques SMB GHOST.<br>
                    Se recomienda su revisión para valorar la actualización de los servicios SMB en la red.<br>
                </p>
                <p>
                    Listado de hosts vulnerables a ataques SMB GHOST:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, output from smbghost WHERE vunl = 'SI'")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES SMB GHOST</h2>
                   <p>
                       El escáner ha detectado que los hosts de la red son <span style='color:green'>NO vulnerables</span> a ataques SMB GHOST.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_rpc(onlyname):
    # Encargado de generar la sección de vulnerabilidades RPC
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM rpc WHERE vunl = 'SI'")
    howmany = cursor.fetchone()
    # Si existe vulnerabilidad
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES RPC</h2>
                <p>
                    El escáner ha detectado hosts <span style='color:red'>vulnerables</span> a ataques RPC.<br>
                    Se recomienda su revisión para valorar la desactivación o limitación de acceso a los servicios RPC en la red.<br>
                </p>
                <p>
                    Listado de hosts vulnerables a ataques RPC:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                        <th>Fichero de registro disponible</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, output from rpc WHERE vunl = 'SI'")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera codigo HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                            <td>{output}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]), output=str(row[2]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        logfile = scriptdir + '/audits/' + onlyname + '.rpc_Dirección_IP_DEL_HOST.log'
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES RPC</h2>
                   <p>
                       El escáner ha detectado que los hosts de la red son <span style='color:green'>NO vulnerables</span> a ataques RPC.
                   </p>
                   <br>
           """.format(logfile=logfile)
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_snmp(onlyname):
    # Encargado de generar la sección de vulnerabilidades SNMP
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM snmp WHERE vunl = 'SI'")
    howmany = cursor.fetchone()
    # Si existe vulnerabilidad
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES SNMP</h2>
                <p>
                    El escáner ha detectado hosts <span style='color:red'>vulnerables</span> a ataques de diccionario simple contra SNMP.<br>
                    Se recomienda su revisión para valorar el cambio del nombre de comunidad SNMP o retringir el acceso a la misma.<br>
                </p>
                <p>
                    Listado de hosts vulnerables a ataques SNMP:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                        <th>Fichero de registro disponible</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, output from snmp WHERE vunl = 'SI'")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                            <td>{output}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]), output=str(row[2]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES SNMP</h2>
                   <p>
                       El escáner ha detectado que los hosts de la red son <span style='color:green'>NO vulnerables</span> a ataques simples de diccionario SNMP.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_smtp(onlyname):
    # Encargado de generar la sección de vulnerabilidades SMTP
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM smtp WHERE vunl = 'SI'")
    howmany = cursor.fetchone()
    # Si existe vulnerabilidad
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES SMTP</h2>
                <p>
                    El escáner ha detectado hosts <span style='color:red'>vulnerables</span> a ataques SMTP.<br>
                    Se recomienda su revisión para incluir una capa de autenticacion en los servidores SMTP de la red.<br>
                </p>
                <p>
                    Listado de hosts vulnerables a ataques SMTP:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                        <th>Fichero de registro disponible</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, output from smtp WHERE vunl = 'SI'")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                            <td>{output}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]), output=str(row[2]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES SMTP</h2>
                   <p>
                       El escáner ha detectado que los hosts de la red son <span style='color:green'>NO vulnerables</span> a ataques SMTP.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_guest(onlyname):
    # Encargado de generar la sección de vulnerabilidades de cuentas de invitado
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM guest WHERE vunl = 'SI'")
    howmany = cursor.fetchone()
    # Si existe vulnerabilidad
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES POR CUENTAS DE INVITADO</h2>
                <p>
                    El escáner ha detectado hosts <span style='color:red'>vulnerables</span> a uso de cuentas de invitados.<br>
                    Se recomienda su revisión para valorar la desactivación de las cuentas de invitado en la red.<br>
                </p>
                <p>
                    Listado de hosts con cuentas de invitado activas:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                        <th>Fichero de registro disponible</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, output from guest WHERE vunl = 'SI'")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                            <td>{output}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]), output=str(row[2]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES POR CUENTAS DE INVITADO</h2>
                   <p>
                       El escáner ha detectado que los hosts de la red son <span style='color:green'>NO vulnerables</span> a ataques por cuentas de invitado activas.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_web(onlyname):
    # Encargado de generar la sección de vulnerabilidades WEB
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM web")
    howmany = cursor.fetchone()
    # Si existen servidores web en la red
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES WEB</h2>
                <p>
                    El escáner ha detectado hosts con servicios WEB en la red.<br>
                    Se recomienda la revisión de los registros generados por el escáner de servicios WEB.<br>
                    El escáner WEB unicamente utiliza las IPs de los hosts y las path por defecto '/' por lo que no comprueba VirtualHost.<br>
                </p>
                <p>
                    Listado de hosts con servicios WEB:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                        <th>Puerto servicio web</th>
                        <th>Fichero de registro disponible</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, vunl, output from web")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                            <td>{vunl}</td>
                            <td>{output}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]), vunl=str(row[2]), output=str(row[3]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES WEB</h2>
                   <p>
                       El escáner no ha detectado hosts en la red ejecutando servicios WEB o estas ejecutando el escáner en un dispotivo ARM sin soporte para el escáner de red ARACHNI.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_brute(onlyname):
    # Encargado de generar la sección de vulnerabilidades Brute Force Attack
    # Variables para uso en la función
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    dbname = scriptdir + '/audits/' + onlyname + '.db'
    # Se consulta base de datos SQLITE
    connection = sqlite3.connect(dbname)
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM brute")
    howmany = cursor.fetchone()
    # Si existen servidores web en la red
    if (howmany[0] > 0):
        html_str = """\
                <h2>RESULTADO DE VULNERABILIDADES A ATAQUES DE FUERZA BRUTA</h2>
                <p>
                    El escáner ha detectado hosts con servicios vulnerables a ataques de fuerza bruta en la red.<br>
                    Cualquier servicio de red debe limitar el número de intentos de acceso no autorizado o crear una alarma cuando se detecte un intento de acceso por fuerza bruta.<br>
                </p>
                <p>
                    Listado de hosts con servicios vulnerables a ataques de Fuerza Bruta:
                </p>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Comando ejecutado</th>
                        <th>Puerto servicio vulnerable</th>
                        <th>Fichero de registro disponible</th>
                    </tr>
        """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        # Se consulta base de datos SQLITE para tabla de hosts vulnerables
        connection = sqlite3.connect(dbname)
        cursor = connection.cursor()
        cursor.execute("SELECT ip, command, vunl, output from brute")
        html_file = open(htmlfile, "a")
        while True:
            row = cursor.fetchone()
            if row is None:
                connection.close()
                break
            # Se genera código HTML de reporte con los valores obtenidos desde SQLITE a modo de tabla
            html_str = """\
                        <tr>
                            <td>{ip}</td>
                            <td>{commmand}</td>
                            <td>{vunl}</td>
                            <td>{output}</td>
                        </tr>
            """.format(ip=str(row[0]), commmand=str(row[1]), vunl=str(row[2]), output=str(row[3]))
            html_file.write(html_str)
        html_str = """\
                </table>
                <br>
         """
        html_file.write(html_str)
        html_file.close()
    # Si NO existe vulnerabilidad
    else:
        # Se genera código HTML de reporte de NO vulnerabilidad
        html_str = """\
                   <h2>RESULTADO DE VULNERABILIDADES A ATAQUES DE FUERZA BRUTA</h2>
                   <p>
                       El escáner no ha detectado hosts en la red con servicios WEB activos y aparentemente vulnerables a ataques de fuerza bruta.
                   </p>
                   <br>
           """
        html_file = open(htmlfile, "a")
        html_file.write(html_str)
        html_file.close()


def tr_logger(onlyname):
    # Encargado de cerrar el código HTML del reporte
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    html_file = open(htmlfile, "a")
    html_str = """\
            <br>
            <h1>LANAudit - FIN DE REPORTE EJECUTIVO</h1>
            <p>
                LANAudit - Update 2022 Q2 <br>
                https://github.com/israelt/lanaudit2022 <br> 
                Master Ciberseguridad TSS <br>
                Autor - Israel Torres <br>
            </p>
            <br>
        </body>
    </html>
        """
    html_file.write(html_str)


def tr_print(onlyname):
    # Encargado de generar el informe en PDF
    htmlfile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.html'
    pdffile = scriptdir + '/audits/' + onlyname + '_reporte_ejecutivo.pdf'
    cmd = 'weasyprint ' + htmlfile + ' ' + pdffile + ' -p'
    os.system(cmd)


def do(onlyname, brute = '1'):
    tr_ipconfig(onlyname)
    tr_nmap(onlyname)
    tr_dhcp(onlyname)
    tr_netbios(onlyname)
    tr_smb(onlyname)
    tr_smbghost(onlyname)
    tr_rpc(onlyname)
    tr_snmp(onlyname)
    tr_smtp(onlyname)
    tr_guest(onlyname)
    if '64' in (os.uname()[2]):
        tr_web(onlyname)
    if brute == 1:
        tr_brute(onlyname)
    tr_logger(onlyname)
    tr_print(onlyname)
    return 0
