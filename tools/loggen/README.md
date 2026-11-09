# loggen

Generator de log-uri SSH și firewall de test pentru LogSentinel SIEM.
Scrie exact formatul citit de `LogEntry` și `FirewallEntry`, deci fișierele se încarcă direct cu opțiunea `[8]` din aplicație.

Necesită doar Python 3.8+ (fără biblioteci externe).

## Mod interactiv

Rulat fără argumente, te întreabă pe rând: tipul de log, câte linii, scenariul, câte să fie eșecuri (restul sunt Accepted) sau pachete blocate, adresele și fișierul. Enter alege valoarea din paranteze.

```
$ python3 tools/loggen/loggen.py
Tip log (ssh / fw) [ssh]: ssh
Cate linii [20]: 30
Scenariu (normal / bruteforce / success-after-fail) [normal]: bruteforce
Cate esecuri (Failed)? intre 21 si 30, Enter = automat [auto]: 22
  -> 22 esecuri, 8 Accepted
Adrese (local / public / subnet / ip) [local]: subnet
Subnet [192.168.1.0/24]: 192.168.50.0/24
Fisier de iesire [ssh_gen.log]:
[OK] 30 linii ssh (bruteforce) scrise in ssh_gen.log
[INFO] In LogSentinel:  load ssh ssh_gen.log   apoi   scan
[INFO] 30 linii: 22 Failed, 8 Accepted, 3 IP-uri unice
```

## Din linia de comandă

```bash
python3 tools/loggen/loggen.py --help
python3 tools/loggen/loggen.py ssh -n 20 --fails 7 -o ssh_gen.log                  # exact 7 Failed + 13 Accepted
python3 tools/loggen/loggen.py ssh -n 20 --subnet 192.168.1.0/24 --scenario bruteforce -o ssh_gen.log
python3 tools/loggen/loggen.py fw  -n 50 --blocked 30 --scenario portscan -o fw_gen.log
```

Atacul are nevoie de un minim de eșecuri (un brute-force e făcut doar din eșecuri). Dacă ceri prea puține, programul îți spune intervalul permis.

| Tip | Scenarii |
|---|---|
| `ssh` | `normal`, `bruteforce`, `success-after-fail` |
| `fw` | `normal`, `portscan`, `slowscan` |

Adrese: `--ip X`, `--subnet CIDR`, `--addr local` (rețele private, implicit) sau `--addr public`.
Pentru un atac multi-stage generezi `fw` + `ssh` cu același `--attacker`.
`--seed` dă același rezultat la fiecare rulare (util pentru teste).

## Date de antrenare pentru modelele statistice

`--labels` adaugă IP-ul atacatorului în fișierul de etichete. Orice IP care nu apare acolo e trafic normal.

```bash
for i in $(seq 1 30); do
  python3 tools/loggen/loggen.py fw  -n 40 -s portscan   --attacker 10.9.0.$i --seed $i --start "2026-11-06 10:00" >> train_fw.log
  python3 tools/loggen/loggen.py ssh -n 40 -s bruteforce --attacker 10.9.0.$i --seed $i --start "2026-11-06 10:05" --labels train_labels.txt >> train_ssh.log
  python3 tools/loggen/loggen.py ssh -n 40 -s normal --seed $((i+100)) --start "2026-11-06 12:00" >> train_ssh.log
done
```
