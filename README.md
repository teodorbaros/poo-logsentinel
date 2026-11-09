# LogSentinel SIEM - Sistem de Analiză Corelată pentru Log-uri SSH și Firewall

**LogSentinel SIEM** este o aplicație interactivă în C++ orientată pe obiecte, destinată monitorizării evenimentelor de securitate, detecției atacurilor de tip **SSH Brute-Force** și **Firewall Port Scanning**, precum și corelării atacurilor *multi-stage* (recunoaștere de rețea urmată de compromiterea autentificării).

---

## Cum rulezi programul

### 1. Compilare (o singură dată, apoi după fiecare modificare)

Ai nevoie de CMake și de un compilator C++20 (g++, clang sau Visual Studio). Din folderul proiectului:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
cmake --install build
```

Programul compilat ajunge în `install_dir/bin/`, împreună cu folderul `assets/` (log-urile de exemplu).

### 2. Pornire

```bash
cd install_dir/bin
./oop_main            # pe Windows: oop_main.exe
```

La pornire apare meniul, cu toate comenzile în ordinea numerelor. După aceea vezi doar promptul `logsentinel>`. Meniul complet și explicațiile le aduci înapoi oricând cu `help`.

### 3. Prima sesiune

```
logsentinel> load ssh assets/sample_ssh.log      încarci log-uri SSH de exemplu
logsentinel> load fw assets/sample_fw.log        și pachete de firewall
logsentinel> scan                                cauți atacuri; la final te întreabă ce IP-uri pui în blacklist
logsentinel> ip 198.51.100.23                    tot ce a făcut atacatorul din exemplu
logsentinel> blacklist howto 198.51.100.23       comanda care îl blochează în firewall
logsentinel> exit
```

Pentru orice comandă, `help <comanda>` îți arată sintaxa și exemple (de exemplu `help scan`). Ghidurile: `help logs` (formatul log-urilor), `help liste` (whitelist / blacklist), `help alerte` (ce înseamnă fiecare alertă), `help generator` (generatorul de log-uri).

### 4. Log-uri de test noi: generatorul Python

Generatorul e un script separat de aplicație, aflat în proiect la **`tools/loggen/loggen.py`**. Are nevoie doar de Python 3 și se rulează **din folderul proiectului, într-un alt terminal** (nu din LogSentinel):

```bash
python3 tools/loggen/loggen.py                                # te întreabă pe rând tot ce trebuie
python3 tools/loggen/loggen.py ssh -n 20 --fails 7 -o test.log  # direct: 20 linii SSH, 7 parole greșite
python3 tools/loggen/loggen.py -h                             # toate opțiunile
```

Fișierul generat îl încarci apoi în LogSentinel cu `load ssh <cale către fișier>`. Toate opțiunile sunt în [`tools/loggen/README.md`](tools/loggen/README.md).

### 5. Log-urile reale ale calculatorului

```bash
sudo ./oop_main       # Linux: log-urile de sistem cer permisiuni
```
```
logsentinel> local ssh 30      încercările de logare SSH din ultimele 30 de minute
logsentinel> local fw 60       pachetele văzute de firewall în ultima oră
logsentinel> scan
```

Pe Windows pornești terminalul ca Administrator. Pe macOS scanarea locală nu e încă disponibilă.

### 6. Rulare cu un scenariu din fișier

```bash
./oop_main < tastatura.txt
```

`tastatura.txt` conține comenzile (și răspunsurile la întrebări) pe care CI-ul le rulează la fiecare push.

---

## Arhitectura (21 de clase, legate prin compunere)

**Date și adrese**
1. **`Timestamp`**: momentul unui eveniment (secunde de la 1 ianuarie), cu validarea lunii, zilei și orei.
2. **`Ipv4Address`**: adresă IPv4 validată, ținută ca text și ca număr pe 32 de biți; știe dacă e privată.
3. **`IpRange`**: un IP sau un subnet CIDR (`192.168.1.0/24`): apartenență și suprapunere prin măști de biți.
4. **`LogEntry`**: o încercare de autentificare SSH (`Timestamp` + `Ipv4Address` + reușită/eșec).
5. **`FirewallEntry`**: un pachet de firewall (port, protocol, BLOCK/ALLOW, porturi critice).

**Surse și detecție**
6. **`LogSource`** / 7. **`FirewallSource`**: ingestie (input, fișier, log-uri locale), validare, sortare cronologică, statistici.
8. **`DetectionPolicy`**: pragurile de detecție și deciziile „e brute-force?”, „e port scan?”, „a ieșit din fereastră?”.
9. **`IpTracker`** / 10. **`PortScanTracker`**: contoarele pe fereastră de timp pentru un IP.
11. **`Alert`**: alertă cu severitate (`MEDIUM` / `HIGH` / `CRITICAL`); constructor de copiere, `operator=` și destructor, folosite la arhivare și escaladare.
12. **`Analyzer`**: motorul SIEM: brute-force SSH, port scan, corelare multi-stage (o alertă per IP), whitelist și blacklist.

**Răspuns la incidente**
13. **`IpList`**: whitelist / blacklist cu motive, salvate în fișier.
14. **`FirewallBlockAdvisor`**: comenzile de blocare, anulare și verificare pentru ufw sau Windows Firewall.
15. **`SubnetProposal`** / 16. **`SubnetEscalator`**: propun blocarea unui /24 sau /16 doar când se adună IP-uri rele în aceeași rețea.
17. **`LocalLogCollector`**: citește log-urile reale ale sistemului (Linux: `journalctl`; Windows: Event Log și `pfirewall.log`).

**Consolă**
18. **`CommandInfo`**: o comandă (număr, nume, sintaxă, descriere); din ea se generează meniul, `help` și mesajele de eroare.
19. **`HelpTopic`**: un ghid din `help` care nu e o comandă (`help logs`, `help liste`, `help alerte`, `help generator`).
20. **`ConsoleBox`**: chenarul de text pentru meniu și rapoarte; completează fiecare rând la aceeași lățime, ca marginile să fie drepte.
21. **`SiemConsoleApp`**: consola: citește comenzile și le trimite claselor de mai sus.

---

## Funcționalitățile Aplicației

Meniul (în chenar, cu comenzile în ordinea numerelor) apare la pornire și cu `help`; după fiecare comandă rămâne un prompt scurt (`logsentinel>`). Comenzile se pot scrie cu număr sau cu nume (`4` sau `scan`), fiecare spune ce a făcut, iar orice argument greșit afișează sintaxa corectă.

| Comandă | Ce face |
|---|---|
| `1` / `ingest-ssh`, `2` / `ingest-fw` | Citește N linii SSH / firewall din input și afișează statistici (valide, respinse, interval, IP-uri unice) |
| `3` / `policy` | Schimbă pragurile de detecție (afișează valorile vechi → noi; refuză valorile invalide) |
| `4` / `scan` | Scanare completă și corelare, apoi întreabă ce IP-uri se adaugă în blacklist (`da` / `nu` / `toate` / `niciunul`) |
| `5` / `ip` | Investighează un IP: fiecare încercare SSH și fiecare pachet de firewall, alertele lui și dacă e în vreo listă. Arată dacă atacul a reușit (o logare reușită după multe parole greșite), ce porturi a căutat și ce poți face mai departe (blacklist, comanda de blocare, whitelist) |
| `6` / `archive` | Arhivează alerta prioritară și versiunea ei escaladată la Tier-2 |
| `7` / `status` | Telemetrie, politică, liste și arhiva de incidente |
| `8` / `load` | Încarcă log-uri dintr-un fișier: `load ssh assets/sample_ssh.log` |
| `9` / `help` | Ce face aplicația, primii pași și toate comenzile; `help <comanda>` pentru sintaxă și exemple; ghiduri: `help logs` (formate), `help liste` (whitelist/blacklist), `help alerte`, `help generator` (unde e și cum rulezi generatorul Python) |
| `10` / `show` | Primele N înregistrări: `show fw 20` |
| `11` / `local` | Log-urile reale din ultimele N minute: `local ssh 30` (Linux cu `sudo`, Windows ca Administrator; macOS planificat) |
| `12` / `whitelist` | `add` / `remove` / `list`: IP-uri de încredere, fără alerte |
| `13` / `blacklist` | `add` / `remove` / `list` / `howto` / `export` / `escalate`: IP-uri rele, comenzi de blocare, escaladare pe subnet. **Aplicația nu modifică firewall-ul singură.** |
| `0` / `exit` | Ieșire și rezumatul sesiunii |

### Generator de log-uri (`tools/loggen/`)

Script Python separat de aplicație, aflat la **`tools/loggen/loggen.py`**, care generează log-uri de test în formatul citit de aplicație: alegi câte linii, câte să fie parole greșite (restul sunt logări reușite), ce adrese și ce atac. Detalii în [`tools/loggen/README.md`](tools/loggen/README.md); pe scurt în aplicație, cu `help generator`.
Fișierele din `assets/` sunt generate cu el.

```bash
python3 tools/loggen/loggen.py                                    # mod interactiv
python3 tools/loggen/loggen.py ssh -n 20 --fails 7 -o ssh_gen.log  # 7 Failed + 13 Accepted
```

### Rulare automată (cron)

Aplicația citește comenzile din input, deci poate rula fără meniu, cu comenzile dintr-un fișier `cron_commands.txt`:

```
local ssh 10
local fw 10
scan
niciunul
exit
```

```cron
# sudo crontab -e  -> la fiecare 10 minute, raportul se adaugă în fișier
*/10 * * * * cd /opt/logsentinel && ./oop_main < cron_commands.txt >> /var/log/logsentinel/report.log 2>&1
```

* Intervalul din cron și minutele din `local` trebuie să fie egale, ca să nu sari peste evenimente sau să le numeri de două ori.
* Folosește căi absolute (cron pornește cu un `PATH` minimal) și creează o dată directorul: `sudo mkdir -p /var/log/logsentinel`.
* Pe Windows: `schtasks /Create /TN "LogSentinel" /SC MINUTE /MO 10 /RU SYSTEM /TR "cmd /c cd /d C:\logsentinel && oop_main.exe < cron_commands.txt >> report.log 2>&1"`

### Planificat (Tema 2)

* Modele statistice pentru probabilitatea de atac (lanțuri Markov, regresie logistică), ca ierarhie de clase cu funcție virtuală `attackProbability()`, antrenate pe date generate cu `tools/loggen`.
* Detecția scanărilor lente (tip `nmap -T1`): fereastră lungă și regularitatea pauzelor dintre pachete.

---

### Tema 0

- [x] Nume proiect (poate fi schimbat ulterior)
- [x] Scurtă descriere a temei alese, ce v-ați propus să implementați

## Tema 1

#### Cerințe

- [x] definirea a minim **3-4 clase** folosind compunere cu clasele definite de voi; moștenirile nu se iau în considerare aici
- [x] constructori de inițializare cu parametri pentru fiecare clasă
- [x] pentru o aceeași (singură) clasă: constructor de copiere, `operator=` de copiere, destructor

- [x] `operator<<` pentru **toate** clasele pentru afișare (`std::ostream`) folosind compunere de apeluri cu `operator<<`
- [x] cât mai multe `const` (unde este cazul) și funcții `private`
- [x] implementarea a minim 3 funcții membru publice pentru funcționalități netriviale specifice temei alese, dintre care cel puțin 1-2 funcții mai complexe
  * nu doar citiri/afișări sau adăugat/șters elemente într-un/dintr-un vector
- [x] scenariu de utilizare **cu sens** a claselor definite:
  * crearea de obiecte și apelarea tuturor funcțiilor membru publice în main
  * vor fi adăugate în fișierul `tastatura.txt` DOAR exemple de date de intrare de la tastatură (dacă există); dacă aveți nevoie de date din fișiere, creați alte fișiere separat
- [x] minim 52-60% din codul propriu să fie C++, `.gitattributes` configurat corect
- [x] tag de `git`: de exemplu `v0.1`
- [x] serviciu de integrare continuă (CI) cu **toate bifele**; exemplu: GitHub Actions
- [ ] code review #1 2 proiecte

## Resurse

- [mcmarius/oop-template](https://github.com/mcmarius/oop-template): template-ul proiectului
- `tools/loggen/loggen.py`: generator propriu de log-uri de test (Python 3, fără biblioteci externe); a generat `assets/sample_ssh.log` și `assets/sample_fw.log`
- Formate de log: OpenSSH (`journalctl`), ufw / netfilter (`SRC=`, `DPT=`), Windows Security Event Log (4624 / 4625), Windows Firewall (`pfirewall.log`)
