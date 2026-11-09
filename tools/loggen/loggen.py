#!/usr/bin/env python3
"""
loggen.py - generator de log-uri de test pentru LogSentinel SIEM.

Scrie linii in formatul pe care il citesc deja clasele din proiectul C++:

  SSH (LogEntry):       Nov 06 14 02 10 192.168.1.50 1
                        luna zi ora min sec  IP  failed (1 = esec, 0 = succes)

  Firewall (FirewallEntry):
                        Nov 06 14 01 05 192.168.1.50 445 TCP 1
                        luna zi ora min sec  IP  port protocol blocked (1 = BLOCK, 0 = ALLOW)

Fisierul generat se incarca in aplicatie cu optiunea [8]:  8 ssh ssh_gen.log
"""

import argparse
import ipaddress
import random
import sys
from datetime import datetime, timedelta

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# Retelele private (RFC 1918) - optiunea --addr local
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

# Porturile pe care FirewallEntry le considera critice + cateva uzuale
CRITICAL_PORTS = [21, 22, 23, 445, 1433, 3306, 3389]
COMMON_PORTS = [25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 5900, 8080, 8443]

SCENARIOS = {
    "ssh": ["normal", "bruteforce", "success-after-fail"],
    "fw": ["normal", "portscan", "slowscan"],
}

EXAMPLES = """
exemple:
  %(prog)s ssh -n 20 --subnet 192.168.1.0/24 --scenario bruteforce -o ssh_gen.log
  %(prog)s ssh -n 40 --addr public --scenario success-after-fail
  %(prog)s fw  -n 50 --addr local --scenario portscan -o fw_gen.log
  %(prog)s fw  -n 30 --scenario slowscan --interval 15        (ca nmap -T1)

atac multi-stage (acelasi IP in ambele fisiere):
  %(prog)s fw  -n 30 --scenario portscan   --attacker 10.0.0.66 -o fw_ms.log
  %(prog)s ssh -n 30 --scenario bruteforce --attacker 10.0.0.66 -o ssh_ms.log

in LogSentinel:
  8 ssh ssh_gen.log      apoi  4  (scanare)
"""


# ---------------------------------------------------------------- adrese IP

class IpPool:
    """Alege adrese IPv4 aleatoare dintr-o sursa: un IP, un subnet, retele locale sau publice."""

    def __init__(self, rng, single=None, subnet=None, mode="local"):
        self.rng = rng
        self.networks = []
        self.public = False
        if single:
            self.networks = [ipaddress.ip_network(single + "/32")]
        elif subnet:
            self.networks = [ipaddress.ip_network(subnet, strict=False)]
        elif mode == "public":
            self.public = True
        else:
            self.networks = PRIVATE_NETS

    def random_ip(self):
        if self.public:
            while True:  # incercam pana nimerim o adresa publica valida
                ip = ipaddress.IPv4Address(self.rng.getrandbits(32))
                if ip.is_global and not ip.is_multicast:
                    return str(ip)
        net = self.rng.choice(self.networks)
        if net.num_addresses <= 2:  # /32 sau /31: nu exista adresa de retea/broadcast
            return str(net.network_address + self.rng.randrange(net.num_addresses))
        # sarim peste adresa de retea (.0) si cea de broadcast
        offset = self.rng.randrange(1, net.num_addresses - 1)
        return str(net.network_address + offset)


# ------------------------------------------------------------- formatare

def stamp(t):
    """datetime -> 'Nov 06 14 02 10' (exact cum citeste LogEntry)."""
    return f"{MONTHS[t.month - 1]} {t.day:02d} {t.hour:02d} {t.minute:02d} {t.second:02d}"


def ssh_line(t, ip, failed):
    return f"{stamp(t)} {ip} {1 if failed else 0}"


def fw_line(t, ip, port, proto, blocked):
    return f"{stamp(t)} {ip} {port} {proto} {1 if blocked else 0}"


# --------------------------------------------------------------- scenarii

def bad_flags(rng, count, bad, default_ratio):
    """Lista de `count` valori True/False: exact `bad` de True (sau ~default_ratio daca bad e None), amestecate."""
    if bad is None:
        return [rng.random() < default_ratio for _ in range(count)]
    flags = [True] * bad + [False] * (count - bad)
    rng.shuffle(flags)
    return flags


def background_ssh(rng, pool, start, count, span, fails=None):
    """Trafic SSH normal: mai multe IP-uri; `fails` = cate esecuri exact (implicit ~15%)."""
    users = [pool.random_ip() for _ in range(max(2, count // 4))]
    events = []
    for failed in bad_flags(rng, count, fails, 0.15):
        t = start + timedelta(seconds=rng.randrange(span))
        events.append((t, ssh_line(t, rng.choice(users), failed)))
    return events


def background_fw(rng, pool, start, count, span, blocked=None):
    """Trafic firewall normal: web permis; `blocked` = cate pachete blocate exact (implicit ~15%)."""
    hosts = [pool.random_ip() for _ in range(max(2, count // 4))]
    events = []
    for is_blocked in bad_flags(rng, count, blocked, 0.15):
        t = start + timedelta(seconds=rng.randrange(span))
        if is_blocked:
            events.append((t, fw_line(t, rng.choice(hosts), rng.choice(COMMON_PORTS), "UDP", True)))
        else:
            events.append((t, fw_line(t, rng.choice(hosts), rng.choice([80, 443]), "TCP", False)))
    return events


def attack_bruteforce(rng, attacker, start, count, interval, end_with_success):
    """Esecuri SSH rapide de la acelasi IP; optional, ultima incercare reuseste (cont compromis)."""
    events, t = [], start
    for i in range(count):
        t += timedelta(seconds=max(1, round(rng.uniform(0.5, 1.5) * interval)))
        failed = not (end_with_success and i == count - 1)
        events.append((t, ssh_line(t, attacker, failed)))
    return events


def attack_portscan(rng, attacker, start, count, interval, jitter):
    """Porturi distincte lovite de acelasi IP; jitter mic = ritm de masina (ca nmap)."""
    candidates = CRITICAL_PORTS + COMMON_PORTS + rng.sample(range(1, 65536), max(0, count))
    ports = list(dict.fromkeys(candidates))[:count]  # unice, in ordine
    rng.shuffle(ports)
    events, t = [], start
    for port in ports:
        t += timedelta(seconds=max(1, round(interval * rng.uniform(1 - jitter, 1 + jitter))))
        events.append((t, fw_line(t, attacker, port, "TCP", True)))
    return events


# ---------------------------------------------------- impartirea liniilor

def split_counts(args):
    """(linii de atac, linii de trafic normal) pentru scenariul ales."""
    if args.scenario == "normal":
        return 0, args.count
    noise = round(args.count * args.noise)
    return args.count - noise, noise


def attack_bad(args, attack_count):
    """Cate din liniile de atac sunt esecuri / pachete blocate."""
    if args.scenario == "success-after-fail":
        return max(0, attack_count - 1)  # ultima incercare a atacatorului reuseste
    return attack_count


def bad_range(args):
    """Intervalul permis pentru --fails / --blocked la scenariul si numarul de linii alese."""
    attack_count, noise_count = split_counts(args)
    minimum = attack_bad(args, attack_count)
    return minimum, minimum + noise_count


# ------------------------------------------------------------------- main

def parse_start(text):
    if text is None:
        return datetime.now().replace(microsecond=0)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(f"data invalida: '{text}' (format: 'YYYY-MM-DD HH:MM[:SS]')")


def build_parser():
    p = argparse.ArgumentParser(
        prog="loggen.py",
        description="Genereaza log-uri SSH si firewall de test pentru LogSentinel SIEM.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("type", choices=["ssh", "fw"], help="tipul de log: ssh sau fw (firewall)")
    p.add_argument("-n", "--count", type=int, default=20, help="numarul total de linii (implicit 20)")
    p.add_argument("--fails", type=int,
                   help="ssh: cate linii sa fie esecuri (restul = Accepted). Implicit: ~15%% din traficul normal")
    p.add_argument("--blocked", type=int,
                   help="fw: cate pachete sa fie blocate (restul = ALLOW). Implicit: ~15%% din traficul normal")
    p.add_argument("-s", "--scenario", default="normal",
                   help="ssh: normal | bruteforce | success-after-fail;  fw: normal | portscan | slowscan")

    addr = p.add_mutually_exclusive_group()
    addr.add_argument("--ip", help="toate adresele = acest IP (ex: 10.0.0.5)")
    addr.add_argument("--subnet", help="adrese dintr-un subnet CIDR (ex: 192.168.1.0/24)")
    addr.add_argument("--addr", choices=["local", "public"], default="local",
                      help="local = retele private 10/8, 172.16/12, 192.168/16 (implicit); public = internet")

    p.add_argument("--attacker", help="IP-ul atacatorului (implicit: ales din aceeasi sursa de adrese)")
    p.add_argument("--noise", type=float, default=0.3,
                   help="la scenariile de atac: ce fractiune din linii e trafic normal (implicit 0.3)")
    p.add_argument("--interval", type=float,
                   help="secunde intre pasii atacului (implicit: 2 la bruteforce/portscan, 15 la slowscan)")
    p.add_argument("--start", type=parse_start, help="ora de start 'YYYY-MM-DD HH:MM[:SS]' (implicit: acum)")
    p.add_argument("--seed", type=int, help="seed pentru rezultate reproductibile")
    p.add_argument("-o", "--output", help="fisierul de iesire (implicit: afisare pe ecran)")
    p.add_argument("--labels", help="adauga 'IP 1' pentru atacator in acest fisier (date de antrenare; "
                                    "IP-urile care lipsesc din fisier sunt considerate trafic normal)")
    return p


def validate(args, parser):
    if args.scenario not in SCENARIOS[args.type]:
        parser.error(f"scenariul '{args.scenario}' nu exista pentru {args.type}. "
                     f"Alege din: {', '.join(SCENARIOS[args.type])}")
    if args.count <= 0:
        parser.error("--count trebuie sa fie > 0")
    if not 0 <= args.noise < 1:
        parser.error("--noise trebuie sa fie intre 0 si 1 (fara 1)")
    for label, value in (("--ip", args.ip), ("--attacker", args.attacker)):
        if value:
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                parser.error(f"{label}: '{value}' nu e o adresa IPv4 valida")
    if args.subnet:
        try:
            ipaddress.IPv4Network(args.subnet, strict=False)
        except ValueError:
            parser.error(f"--subnet: '{args.subnet}' nu e un subnet IPv4 valid (ex: 192.168.1.0/24)")
    if args.type == "ssh" and args.blocked is not None:
        parser.error("--blocked e pentru fw; la ssh foloseste --fails")
    if args.type == "fw" and args.fails is not None:
        parser.error("--fails e pentru ssh; la fw foloseste --blocked")
    bad = args.fails if args.type == "ssh" else args.blocked
    if bad is not None:
        low, high = bad_range(args)
        if not low <= bad <= high:
            what = "esecuri" if args.type == "ssh" else "pachete blocate"
            parser.error(f"cu {args.count} linii si scenariul '{args.scenario}' poti avea intre {low} si {high} "
                         f"{what} (atacul are nevoie de {low})")


def generate(args):
    rng = random.Random(args.seed)
    pool = IpPool(rng, single=args.ip, subnet=args.subnet, mode=args.addr)
    start = args.start or parse_start(None)

    attack_count, noise_count = split_counts(args)
    requested_bad = args.fails if args.type == "ssh" else args.blocked
    background_bad = None if requested_bad is None else requested_bad - attack_bad(args, attack_count)

    attacker = args.attacker or pool.random_ip()
    default_interval = 15 if args.scenario == "slowscan" else 2
    interval = args.interval if args.interval is not None else default_interval

    # Atacul incepe dupa primul sfert din trafic; zgomotul acopera toata durata atacului
    attack_span = int(attack_count * interval * 1.5) + 1
    span = max(600, attack_span * 2)
    attack_start = start + timedelta(seconds=span // 4)

    if args.type == "ssh":
        events = background_ssh(rng, pool, start, noise_count, span, background_bad)
        if attack_count:
            events += attack_bruteforce(rng, attacker, attack_start, attack_count, interval,
                                        end_with_success=(args.scenario == "success-after-fail"))
    else:
        events = background_fw(rng, pool, start, noise_count, span, background_bad)
        if attack_count:
            jitter = 0.05 if args.scenario == "slowscan" else 0.3
            events += attack_portscan(rng, attacker, attack_start, attack_count, interval, jitter)

    events.sort(key=lambda e: e[0])
    if events and events[0][0].year != events[-1][0].year:
        print("[WARN] log-ul trece peste 31 decembrie; LogEntry nu stie anul, deci ordinea va fi gresita.",
              file=sys.stderr)
    return [line for _, line in events], (attacker if attack_count else None)


# --------------------------------------------------------- mod interactiv

def ask(question, default, allowed=None, is_int=False):
    """Intreaba pana primeste un raspuns valid; Enter = valoarea implicita."""
    while True:
        try:
            answer = input(f"{question} [{default}]: ").strip() or str(default)
        except EOFError:
            print()
            sys.exit(1)
        if allowed and answer not in allowed:
            print(f"  -> alege din: {', '.join(allowed)}")
        elif is_int and not answer.isdigit():
            print("  -> scrie un numar intreg pozitiv")
        else:
            return answer


def interactive_argv():
    """Construieste argumentele din intrebari (rulare fara argumente)."""
    print("=== LogSentinel - generator de log-uri (Enter = valoarea din paranteze, -h = ajutor complet) ===")
    log_type = ask("Tip log (ssh / fw)", "ssh", ["ssh", "fw"])
    count = ask("Cate linii", 20, is_int=True)
    scenario = ask(f"Scenariu ({' / '.join(SCENARIOS[log_type])})", "normal", SCENARIOS[log_type])
    argv = [log_type, "-n", count, "-s", scenario]

    probe = build_parser().parse_args(argv)
    low, high = bad_range(probe)
    what, flag, rest = ("esecuri (Failed)", "--fails", "Accepted") if log_type == "ssh" \
        else ("pachete blocate (BLOCK)", "--blocked", "ALLOW")
    while True:
        bad = ask(f"Cate {what}? intre {low} si {high}, Enter = automat", "auto")
        if bad == "auto":
            break
        if bad.isdigit() and low <= int(bad) <= high:
            argv += [flag, bad]
            print(f"  -> {bad} {what.split()[0]}, {int(count) - int(bad)} {rest}")
            break
        print(f"  -> scrie un numar intre {low} si {high} sau apasa Enter")

    addr = ask("Adrese (local / public / subnet / ip)", "local", ["local", "public", "subnet", "ip"])
    if addr == "subnet":
        argv += ["--subnet", ask("Subnet", "192.168.1.0/24")]
    elif addr == "ip":
        argv += ["--ip", ask("IP", "10.0.0.5")]
    else:
        argv += ["--addr", addr]
    argv += ["-o", ask("Fisier de iesire", f"{log_type}_gen.log")]
    return argv


def print_summary(args, lines):
    """Statistica liniilor generate."""
    bad = sum(1 for line in lines if line.endswith(" 1"))
    ips = {line.split()[5] for line in lines}
    good_label, bad_label = ("Accepted", "Failed") if args.type == "ssh" else ("ALLOW", "BLOCK")
    print(f"[INFO] {len(lines)} linii: {bad} {bad_label}, {len(lines) - bad} {good_label}, {len(ips)} IP-uri unice",
          file=sys.stderr)


def main():
    parser = build_parser()
    argv = interactive_argv() if len(sys.argv) == 1 else sys.argv[1:]
    args = parser.parse_args(argv)
    validate(args, parser)

    lines, attacker = generate(args)
    text = "\n".join(lines) + "\n"

    if args.output:
        with open(args.output, "w", encoding="ascii", newline="\n") as f:
            f.write(text)
        print(f"[OK] {len(lines)} linii {args.type} ({args.scenario}) scrise in {args.output}", file=sys.stderr)
        print(f"[INFO] In LogSentinel:  load {args.type} {args.output}   apoi   scan", file=sys.stderr)
    else:
        sys.stdout.write(text)
    print_summary(args, lines)
    if attacker:
        print(f"[INFO] IP atacator: {attacker}", file=sys.stderr)
        if args.labels:
            with open(args.labels, "a", encoding="ascii", newline="\n") as f:
                f.write(f"{attacker} 1\n")
            print(f"[OK] eticheta adaugata in {args.labels}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
