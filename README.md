# Yulian - HackMyVM - Hard

![Yulian.png](Yulian.png)

## Übersicht

*   **VM:** Yulian
*   **Plattform:** HackMyVM ([https://hackmyvm.eu/machines/machine.php?vm=Yulian](https://hackmyvm.eu/machines/machine.php?vm=Yulian))
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 02. August 2025
*   **Original-Writeup:** [https://alientec1908.github.io/Yulian_HackMyVM_Hard/](https://alientec1908.github.io/Yulian_HackMyVM_Hard/)
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieses Penetrationstests war die vollständige Kompromittierung der virtuellen Maschine "Yulian" und die Erlangung von Root-Rechten auf dem Host-System. Die Lösung erforderte einen mehrstufigen Ansatz: Zuerst musste ein anfänglich gefilterter Web-Port (8080) mittels einer Reverse-Engineered Port-Knocking-Sequenz geöffnet werden. Dies enthüllte eine Java-Webanwendung mit kritischen Schwachstellen. Eine Local File Inclusion (LFI) in einer Download-Funktion ermöglichte das Extrahieren des Anwendungs-JARs, welches eine Java-Deserialization-Schwachstelle offenbarte. Dies führte zu einem initialen Root-Zugriff innerhalb eines Docker-Containers. Die Privilegien-Eskalation zum Host-Root wurde durch eine `chroot`-Umgehung der Container-Isolation erreicht, die durch exposed Host-Mounts begünstigt wurde. Alternativ wurde ein schwaches Root-Passwort für SSH durch eine angepasste Brute-Force-Attacke geknackt. Zusätzlich wurde ein verschlüsselter SSH-Key für den Benutzer `ldz` durch die Ausnutzung einer XTEA-Verschlüsselungsschwachstelle auf dem Host entschlüsselt, was einen weiteren persistenten Zugriff schuf.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `curl`
*   `Burpsuite`
*   `gcc`
*   `ffuf`
*   `wget`
*   `unzip`
*   `ysoserial`
*   `netcat (nc)`
*   `chisel`
*   `sshpass`
*   `Hydra`
*   `ssh`
*   `git`
*   `python3`
*   `docker`
*   `apk`
*   `strings`
*   `e2fsprogs` (inkl. `debugfs`)
*   Standard Linux-Befehle (`ls`, `cat`, `find`, `grep`, `id`, `uname`, `ip`, `netstat`, `mount`, `chroot`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Yulian" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   Identifizierung der Ziel-IP (192.168.2.166) im lokalen Netzwerk mittels `arp-scan`.
    *   Umfassender `nmap`-Scan identifizierte offene Ports 22 (SSH - OpenSSH 9.9) und 80 (HTTP - Nginx) sowie einen gefilterten Port 8080. Der HTTP-Titel "Linux Terminal Simulator" auf Port 80 wurde bemerkt.
    *   Initialer `nikto`- und `gobuster`-Scan auf Port 80 zeigte fehlende Sicherheits-Header und nur `index.html`.
    *   Durch Reverse Engineering einer lokalen Binary konnte eine Port-Knocking-Sequenz identifiziert werden.
    *   Erfolgreiches Port Knocking öffnete Port 8080, welcher einen Apache Tomcat-Webserver enthüllte.
    *   Erneute `nikto`- und `gobuster`-Scans auf Port 8080 fanden interessante Pfade wie `/login.html`, `/download`, `/success`, `/error` und zeigten erlaubte HTTP-Methoden wie `PUT` und `DELETE`.

2.  **Initial Access (Java Deserialization RCE):**
    *   Die Login-Seite auf Port 8080 (<code>login.html</code>) wies eine schwache Brute-Force-Schutz auf, wodurch das Passwort `123457` für den Benutzer `admin` erfolgreich geknackt werden konnte.
    *   Eine kritische Local File Inclusion (LFI) / Path Traversal-Schwachstelle in der `/download`-Funktion ermöglichte das Auslesen von Systemdateien (z.B. `/proc/self/cmdline`) und das Herunterladen des vollständigen Java-JAR-Archivs (<code>javaserver-0.0.1-SNAPSHOT.jar</code>) der Webanwendung.
    *   Die statische Analyse des dekompilierten JAR-Archivs enthüllte einen Java-Deserialization-Endpunkt (`/deserialize`) und das Vorhandensein anfälliger Bibliotheken (z.B. CommonsCollections).
    *   Eine Reverse Shell-Payload wurde mittels `ysoserial` (CommonsCollections7-Gadget-Chain) generiert.
    *   Durch das Senden der Payload an den `/deserialize`-Endpunkt wurde eine Reverse Shell zum Angreifer initiiert.
    *   **Erfolgreicher Initial Access als Root-Benutzer innerhalb eines Docker-Containers**.

3.  **Privilege Escalation (Container Root zu Host Root):**
    *   Umfassende System- und Netzwerkanalyse im Container (<code>id</code>, <code>hostname</code>, <code>ip a</code>, <code>netstat</code>, <code>uname -a</code>, <code>mount</code>, <code>/proc/1/status</code>, <code>/sys/fs/cgroup</code>) bestätigte die Docker-Umgebung, zeigte weitreichende Linux Capabilities für den Root-Prozess im Container und enthüllte eine kritische Fehlkonfiguration: Host-Dateien wie `/etc/hosts` und `/etc/resolv.conf` waren als Partitionen von `/dev/sda3` Read-Write in den Container gemountet.
    *   **Erfolgreicher Container Breakout zum Host-Root** mittels einer `chroot`-Technik, die den gemounteten Host-Pfad `/etc/..` nutzte, um das Host-Root-Dateisystem zu wechseln.

4.  **Alternative Privilege Escalation (Host SSH Root):**
    *   Ein Chisel-Reverse-Tunnel wurde vom kompromittierten Container zum SSH-Dienst des Host-Systems (<code>172.17.0.1:22</code>) auf den Angreifer-Port <code>127.0.0.1:2222</code> eingerichtet.
    *   Der Quelltext der Nginx-Webseite auf Port 8000 (über den Chisel-Tunnel zugänglich) enthielt einen versteckten HTML-Kommentar: `<!--500-worst-passwords-->`.
    *   Ein `Hydra`-Brute-Force-Versuch auf SSH mit der `rockyou.txt`-Wordlist schlug aufgrund aggressiver Rate-Limitierung des SSH-Dienstes fehl.
    *   Eine angepasste manuelle Brute-Force-Schleife mit `sshpass` und einer Sekunde `sleep` pro Versuch umging erfolgreich die Rate-Limitierung.
    *   **Erfolgreicher SSH-Login als `root` mit dem Passwort `mountain`**.

5.  **Zusätzlicher Lateral Movement (Benutzer `ldz`):**
    *   Die binäre Analyse des `userLogin`-Tools auf dem Host mittels `strings` ergab Hinweise auf einen SSH-Schlüssel (`@@key-for-user-ldzid_ed25519`) und die Verwendung der `xtea_encrypt`-Funktion.
    *   Eine verschlüsselte Datei (`/etc/output.enc`) wurde auf dem Host gefunden.
    *   Mittels eines von GitHub geklonten XTEA-Entschlüsselungstools wurde `/etc/output.enc` entschlüsselt, was einen privaten SSH-Schlüssel für den Benutzer `ldz` enthüllte.
    *   Erfolgreicher SSH-Login als `ldz` mit dem entschlüsselten Schlüssel.

## Wichtige Schwachstellen und Konzepte

*   **Port Knocking:** Mechanismus zur Port-Verdeckung, der durch Reverse Engineering eines Client-Programms und das Nachvollziehen der Sequenz umgangen wurde.
*   **Fehlende HTTP Security Headers:** Anfälligkeit der Webanwendung für clientseitige Angriffe wie Clickjacking (fehlender X-Frame-Options Header) und MIME-Sniffing (fehlender X-Content-Type-Options Header).
*   **Schwacher Brute-Force-Schutz:** Das Login-Formular der Webanwendung auf Port 8080 hatte keine ausreichende Rate-Limitierung, was das Knacken des Administrator-Passworts ermöglichte.
*   **Local File Inclusion (LFI) / Path Traversal:** Die `download`-Funktion der Webanwendung erlaubte das Auslesen beliebiger Dateien vom Server-Dateisystem, bis hin zum vollständigen Herunterladen des Anwendungscodes.
*   **Java Deserialization (Remote Code Execution - RCE):** Eine kritische Schwachstelle in der Java-Anwendung ermöglichte die Ausführung beliebigen Codes auf dem Server durch das Senden eines manipulierten, serialisierten Java-Objekts (nutzte die CommonsCollections7-Gadget-Chain).
*   **Docker Container Breakout (Exposed Host Mounts & `chroot`):** Eine schwerwiegende Fehlkonfiguration, bei der sensible Host-Dateien (z.B. `/etc/hosts`, `/etc/resolv.conf`) von der Host-Partition `/dev/sda3` Read-Write in den Container gemountet wurden. Dies ermöglichte die Umgehung der Container-Isolation mittels eines `chroot`-Tricks (<code>chroot /etc/..</code>) zum Host-Root.
*   **Schwache SSH-Passwörter & Brute-Force-Umgehung:** Das Root-Passwort "mountain" war extrem einfach zu knacken, und die implementierte SSH-Rate-Limitierung konnte durch eine sequentielle Brute-Force-Attacke mit `sshpass` und Pausen umgangen werden.
*   **Informationslecks (Web-Kommentare & Binäranalyse):** Ein versteckter HTML-Kommentar enthielt Hinweise auf eine "worst passwords"-Liste. Die statische Analyse einer Host-Binary enthüllte Hinweise auf SSH-Keys und den verwendeten XTEA-Verschlüsselungsalgorithmus.
*   **XTEA Cryptography Misuse & SSH Key Exposure:** Eine verschlüsselte Datei (`/etc/output.enc`) enthielt einen privaten SSH-Schlüssel, der durch den Hinweis auf den verwendeten Algorithmus (XTEA) und das Herunterladen eines öffentlichen Entschlüsselungstools wiederhergestellt werden konnte.
*   **Linux Capabilities (Docker Container):** Der Root-Prozess im Docker-Container lief mit viel zu weitreichenden Linux Capabilities (z.B. `CAP_SYS_ADMIN`), was das Risiko eines Container Breakouts erheblich erhöhte.

## Flags

*   **User Flag (`/root/user.txt` im Container):** `flag{ce6560c893e5cfec48e0fd186dc03718}`
*   **Root Flag (`/root/root.txt` auf dem Host):** `flag{98ecb90d5dcef41e1bd18f47697f287a}`

## Tags

`HackMyVM`, `Yulian`, `Hard`, `Linux`, `Web`, `Docker`, `Container Escape`, `Java Deserialization`, `RCE`, `LFI`, `Path Traversal`, `SSH`, `Brute Force`, `Password Cracking`, `XTEA`, `Cryptography`, `Privilege Escalation`, `Exploit Development`, `Reconnaissance`, `Web Enumeration`, `Initial Access`
