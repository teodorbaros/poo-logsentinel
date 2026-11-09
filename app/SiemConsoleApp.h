#ifndef SIEM_CONSOLE_APP_H
#define SIEM_CONSOLE_APP_H

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "Alert.h"
#include "Analyzer.h"
#include "CommandInfo.h"
#include "ConsoleBox.h"
#include "DetectionPolicy.h"
#include "FirewallBlockAdvisor.h"
#include "FirewallSource.h"
#include "HelpTopic.h"
#include "IpList.h"
#include "IpRange.h"
#include "LocalLogCollector.h"
#include "LogSource.h"
#include "SubnetEscalator.h"

// Consola: citeste comenzi (nume sau numar) si le trimite la clasa care stie sa le faca.
// Tot ce afiseaza merge in `out_`, nu direct in std::cout, ca sa poata fi redirectat (fisier, teste).
class SiemConsoleApp {
private:
    static constexpr int kDefaultShowCount = 10;
    static constexpr int kMinBadIpsPer24 = 3;
    static constexpr int kMinBad24sPer16 = 3;
    static constexpr int kSuggestionColumn = 40;   // "whitelist add 255.255.255.255 <motiv>" + spatiu

    enum class Answer { Yes, No, All, None };

    std::ostream& out_;
    LogSource sshSource_;
    FirewallSource fwSource_;
    IpList whitelist_;
    IpList blacklist_;
    Analyzer analyzer_;   // declarat DUPA surse si liste: le primeste prin referinta in constructor
    SubnetEscalator escalator_;
    LocalLogCollector localCollector_;
    std::vector<CommandInfo> commands_;
    std::vector<HelpTopic> helpTopics_;
    std::vector<Alert> archivedAlerts_;
    int executedCommands_;
    std::string lastCommand_;

    void registerCommands() {
        commands_.emplace_back(1, "ingest-ssh", "1 <N>, apoi N linii SSH", "scrii log-uri SSH direct in consola",
            "Fiecare linie: luna zi ora minut secunda IP 1/0   (1 = parola gresita, 0 = logare reusita)\n"
            "Exemplu:\n"
            "  1 2\n"
            "  Oct 12 14 02 10 192.168.1.50 1\n"
            "  Oct 12 14 02 15 192.168.1.50 0\n"
            "Liniile gresite (IP invalid, data imposibila) sunt numarate si sarite.");
        commands_.emplace_back(2, "ingest-fw", "2 <N>, apoi N linii de firewall",
            "scrii pachete de firewall direct in consola",
            "Fiecare linie: luna zi ora minut secunda IP port protocol 1/0   (1 = blocat, 0 = permis)\n"
            "Exemplu:\n"
            "  2 1\n"
            "  Oct 12 14 01 05 203.0.113.77 22 TCP 1\n"
            "Protocolul poate fi TCP, UDP sau ICMP; portul intre 1 si 65535.");
        commands_.emplace_back(3, "policy", "policy <parole> <porturi> <secunde> <rata>", "schimbi pragurile de detectie",
            "  parole   cate parole gresite de la acelasi IP inseamna brute-force\n"
            "  porturi  cate porturi diferite blocate inseamna port scan\n"
            "  secunde  in cat timp se numara\n"
            "  rata     ce parte din incercari trebuie sa fie gresite (intre 0 si 1)\n"
            "Exemplu: policy 5 4 60 0.8   (valorile de la pornire)\n"
            "Rata exista ca sa nu alertezi un om care a gresit parola de doua ori si apoi a intrat.\n"
            "Noile praguri se aplica la urmatorul 'scan'.");
        commands_.emplace_back(4, "scan", "scan", "cauta atacuri in log-urile incarcate",
            "Cauta brute-force SSH si port scan, iar cand vin de la acelasi IP le leaga intr-un atac\n"
            "in doua etape. Afiseaza alertele, cele mai grave primele. IP-urile din whitelist sunt sarite.\n"
            "La final te intreaba, pentru fiecare IP periculos, daca il pui in blacklist:\n"
            "  da / nu / toate (restul fara sa mai intrebe) / niciunul (te opresti)");
        commands_.emplace_back(5, "ip", "ip <adresa>", "investighezi un IP: istoric, alerte, liste",
            "Exemplu: ip 198.51.100.23\n"
            "\n"
            "Cand 'scan' iti arata un IP suspect, cu 'ip' afli ce a facut exact:\n"
            "  - fiecare incercare de logare SSH (ora, parola gresita sau logare reusita)\n"
            "  - fiecare pachet vazut de firewall (ora, port, blocat sau permis)\n"
            "  - alertele lui de la ultimul 'scan' si daca e in whitelist sau in blacklist\n"
            "\n"
            "La ce te ajuta:\n"
            "  - vezi daca atacul a reusit: o 'logare reusita' dupa multe parole gresite\n"
            "    inseamna probabil un cont compromis\n"
            "  - vezi ce porturi a cautat (de exemplu 22 = SSH, 3389 = RDP, 445 = SMB)\n"
            "  - deosebesti un atacator de un coleg care si-a uitat parola\n"
            "\n"
            "Ce faci apoi:\n"
            "  blacklist add <ip> <motiv>   il marchezi ca rau\n"
            "  blacklist howto <ip>         comanda care il blocheaza in firewall\n"
            "  whitelist add <ip> <motiv>   daca e de incredere (alarma falsa)");
        commands_.emplace_back(6, "archive", "archive", "arhivezi cel mai grav incident",
            "Ia cel mai grav incident de la ultimul 'scan', pastreaza o copie si il marcheaza ca predat\n"
            "echipei Tier-2 (analistii care investigheaza mai departe). Arhiva o vezi cu 'status'.");
        commands_.emplace_back(7, "status", "status", "ce e incarcat, pragurile, listele si arhiva",
            "Un rezumat al sesiunii: log-urile incarcate, pragurile curente, whitelist, blacklist\n"
            "si incidentele arhivate.");
        commands_.emplace_back(8, "load", "load ssh|fw <fisier>", "incarci log-uri dintr-un fisier",
            "Exemple:\n"
            "  load ssh assets/sample_ssh.log\n"
            "  load fw assets/sample_fw.log\n"
            "Acelasi format ca la comenzile 1 si 2, o inregistrare pe linie (detalii: help logs).\n"
            "Fisiere noi de test generezi cu: python3 tools/loggen/loggen.py");
        commands_.emplace_back(9, "help", "help [comanda | logs | liste | alerte | generator]", "explicatii si exemple",
            "  help            ce face aplicatia si lista comenzilor\n"
            "  help <comanda>  sintaxa si exemple pentru o comanda (ex: help scan)\n"
            "  help logs       formatul log-urilor si de unde le iei\n"
            "  help liste      cum functioneaza whitelist, blacklist si blocarea retelelor\n"
            "  help alerte     ce inseamna fiecare alerta si cat de grava e\n"
            "  help generator  cum generezi log-uri de test cu scriptul Python");
        commands_.emplace_back(10, "show", "show ssh|fw [N]", "vezi primele N inregistrari incarcate",
            "Exemplu: show fw 20   (fara numar: primele 10)\n"
            "Util ca sa verifici ce s-a incarcat, inainte de 'scan'.");
        commands_.emplace_back(11, "local", "local ssh|fw <minute>", "citesti log-urile reale ale calculatorului",
            "Exemple:\n"
            "  local ssh 30   incercarile de logare SSH din ultimele 30 de minute\n"
            "  local fw 60    pachetele vazute de firewall in ultima ora\n"
            "Linux: ruleaza aplicatia cu sudo (log-urile de sistem cer permisiuni).\n"
            "Windows: porneste terminalul ca Administrator.\n"
            "Ce gaseste se adauga la log-urile deja incarcate; apoi rulezi 'scan'.");
        commands_.emplace_back(12, "whitelist", "whitelist add|remove|list [ip sau subnet] [motiv]",
            "IP-uri de incredere, sarite la scanare",
            "IP-urile din whitelist nu genereaza alerte si nu sunt propuse niciodata pentru blocare.\n"
            "Merge si cu o retea intreaga (subnet).\n"
            "Exemple:\n"
            "  whitelist add 192.168.1.20 laptopul meu\n"
            "  whitelist add 10.0.0.0/8 reteaua interna\n"
            "  whitelist remove 192.168.1.20\n"
            "Pune aici IP-ul tau, ca sa nu te blochezi singur. Lista se pastreaza in whitelist.txt.");
        commands_.emplace_back(13, "blacklist", "blacklist add|remove|list|howto|export|escalate ...",
            "IP-uri rele: alerta imediata si comenzi de blocare",
            "Orice activitate a unui IP din blacklist apare ca alerta la 'scan', chiar sub praguri.\n"
            "  blacklist add 45.12.3.9 brute-force   adaugi un IP (sau un subnet) cu motivul\n"
            "  blacklist remove 45.12.3.9            il scoti\n"
            "  blacklist list                         vezi lista\n"
            "  blacklist howto 45.12.3.9             comanda care il blocheaza in firewall\n"
            "  blacklist export block.sh             toate comenzile intr-un script, de citit si rulat\n"
            "  blacklist escalate                    propune blocarea unei retele intregi\n"
            "Aplicatia nu modifica firewall-ul singura: comenzile le rulezi tu. Mai multe: help liste");
        commands_.emplace_back(0, "exit", "exit", "iesi din aplicatie",
            "Inchide aplicatia si afiseaza un rezumat. Listele raman salvate in fisiere.");

        helpTopics_.emplace_back("logs", "formatul log-urilor si de unde le iei",
            "O incercare de logare SSH pe linie:\n"
            "  Oct 12 14 02 10 192.168.1.50 1\n"
            "  luna, zi, ora, minut, secunda, IP, apoi 1 = parola gresita sau 0 = logare reusita\n"
            "\n"
            "Un pachet de firewall pe linie:\n"
            "  Oct 12 14 01 05 203.0.113.77 22 TCP 1\n"
            "  luna, zi, ora, minut, secunda, IP, port, protocol, apoi 1 = blocat sau 0 = permis\n"
            "\n"
            "Liniile gresite (IP invalid, data imposibila, port peste 65535) sunt numarate si sarite.\n"
            "\n"
            "De unde le iei:\n"
            "  load ssh <fisier>             dintr-un fisier (ex: assets/sample_ssh.log)\n"
            "  local ssh 30                  log-urile reale ale calculatorului (Linux / Windows)\n"
            "  1 <N> / 2 <N>                 le scrii direct in consola\n"
            "  python3 tools/loggen/loggen.py   generezi fisiere de test (detalii: help generator)");
        helpTopics_.emplace_back("liste", "whitelist, blacklist si blocarea retelelor",
            "whitelist = IP-uri de incredere. La 'scan' sunt sarite, deci nu dau alerte si nu sunt\n"
            "propuse niciodata pentru blocare.\n"
            "blacklist = IP-uri rele. Orice activitate a lor apare ca alerta, chiar sub praguri.\n"
            "Amandoua accepta adrese (10.0.0.5) si retele (10.0.0.0/24). O adresa nu poate fi in ambele.\n"
            "\n"
            "Dupa 'scan', aplicatia te intreaba pentru fiecare IP periculos daca il pui in blacklist.\n"
            "Blacklist-ul nu blocheaza nimic in firewall. Asta o faci tu, cu comenzile date de:\n"
            "  blacklist howto <ip>        pentru un singur IP\n"
            "  blacklist export block.sh   pentru toate, intr-un script pe care il citesti inainte\n"
            "\n"
            "blacklist escalate se uita dupa retele cu multe IP-uri rele: 3 IP-uri in acelasi /24\n"
            "(256 de adrese) sau 3 retele /24 in acelasi /16. Nu propune niciodata o retea care\n"
            "contine ceva din whitelist sau o retea locala (10.x, 172.16-31.x, 192.168.x).\n"
            "\n"
            "Listele se salveaza in whitelist.txt si blacklist.txt si se citesc la pornire.");
        helpTopics_.emplace_back("alerte", "ce inseamna fiecare alerta",
            "brute-force SSH        un IP a gresit parola de multe ori intr-un timp scurt\n"
            "port scan              un IP a incercat multe porturi, ca sa vada ce servicii ai deschise\n"
            "atac in doua etape     acelasi IP a scanat porturi si apoi a incercat parole\n"
            "IP din blacklist       un IP pe care l-ai marcat ca rau a aparut din nou\n"
            "predat echipei Tier-2  incident arhivat cu 'archive'\n"
            "\n"
            "Gravitate: MEDIUM < HIGH < CRITICAL. Creste cu numarul de incercari, cu porturile\n"
            "critice lovite (SSH, RDP, SMB, baze de date) si e maxima la atacul in doua etape.\n"
            "Pragurile le vezi cu 'status' si le schimbi cu 'policy'.");
        helpTopics_.emplace_back("generator", "generatorul de log-uri de test (Python)",
            "Un script separat de aplicatie, care scrie fisiere de log in formatul de mai sus,\n"
            "ca sa ai pe ce testa fara atacuri reale.\n"
            "\n"
            "Unde e: in proiect, la tools/loggen/loggen.py (are nevoie doar de Python 3).\n"
            "\n"
            "Cum il rulezi, din folderul proiectului (intr-un alt terminal, nu in LogSentinel):\n"
            "  python3 tools/loggen/loggen.py\n"
            "      te intreaba pe rand: ssh sau firewall, cate linii, ce atac, cate sa fie parole\n"
            "      gresite (restul sunt logari reusite), ce adrese si in ce fisier sa scrie\n"
            "  python3 tools/loggen/loggen.py ssh -n 20 --fails 7 -o test.log\n"
            "      direct: 20 de linii SSH, din care 7 parole gresite\n"
            "  python3 tools/loggen/loggen.py fw -n 30 -s portscan -o scan.log\n"
            "      30 de pachete de firewall, cu un port scan in ele\n"
            "  python3 tools/loggen/loggen.py -h\n"
            "      toate optiunile: atacuri (bruteforce, portscan, slowscan...), subnet, IP fix\n"
            "\n"
            "Apoi, in LogSentinel:\n"
            "  load ssh test.log\n"
            "  scan\n"
            "Fisierele din assets/ (sample_ssh.log, sample_fw.log) sunt facute tot cu el.");
    }

    const CommandInfo* findCommand(const std::string& token) const {
        for (const CommandInfo& cmd : commands_) {
            if (cmd.matches(token)) {
                return &cmd;
            }
        }
        return nullptr;
    }

    void printUsage(const std::string& keyword) const { findCommand(keyword)->printUsageError(out_); }

    // restul liniei curente, pentru comenzile cu argumente optionale (cu >> am astepta urmatoarea linie)
    static std::string restOfLine(std::istream& in) {
        std::string rest;
        std::getline(in, rest);
        return rest;
    }

    // da / nu / toate / niciunul; final de input = niciunul (ca sa nu ramana blocat)
    Answer askConfirmation(std::istream& in, const std::string& question) const {
        while (true) {
            out_ << "  " << question << " [da/nu/toate/niciunul] ";
            std::string word;
            if (!(in >> word)) {
                return Answer::None;
            }
            if (word == "da") {
                return Answer::Yes;
            }
            if (word == "nu") {
                return Answer::No;
            }
            if (word == "toate") {
                return Answer::All;
            }
            if (word == "niciunul") {
                return Answer::None;
            }
            out_ << "  Raspunde cu da, nu, toate sau niciunul.\n";
        }
    }

    // Folosita si dupa scan (IP-uri) si la escaladare (retele): intreaba pentru fiecare, adauga in blacklist
    // cu motivul lui. Intoarce cate a adaugat.
    int confirmAndBlacklist(std::istream& in, const std::vector<IpRange>& targets,
                            const std::vector<std::string>& reasons) {
        bool addAll = false;
        int added = 0;
        for (std::size_t i = 0; i < targets.size(); i++) {
            Answer answer = Answer::Yes;
            if (!addAll) {
                answer = askConfirmation(in, targets[i].toText() + " (" + reasons[i] + ") - il pui in blacklist?");
            }
            if (answer == Answer::None) {
                break;
            }
            addAll = addAll || answer == Answer::All;
            if (answer != Answer::No && blacklist_.add(targets[i].toText(), reasons[i], out_)) {
                added++;
            }
        }
        if (added > 0) {
            out_ << "Blacklist-ul nu blocheaza nimic in firewall. Comenzile de blocare: 'blacklist howto <ip>'\n"
                 << "pentru unul sau 'blacklist export block.sh' pentru toate.\n";
        }
        return added;
    }

    // o comanda pe un rand:  "   4  scan          cauta atacuri in log-urile incarcate"
    std::string commandLine(const std::string& number) const {
        std::ostringstream line;
        line << "  " << *findCommand(number);
        return line.str();
    }

    // comenzile, in ordinea numerelor (lista e inregistrata deja asa), cu 0 / exit la final
    void addCommandSections(ConsoleBox& box) const {
        box.addLine("COMENZI (scrii numarul sau numele)");
        for (const CommandInfo& cmd : commands_) {
            box.addLine(commandLine(cmd.getKeyword()));
        }
    }

    void printStartup() const {
        ConsoleBox box;
        box.addTitle("LOGSENTINEL SIEM", "analiza log-urilor SSH si firewall").addRule();
        addCommandSections(box);
        box.addRule()
            .addLine("Detalii si exemple pentru orice comanda: help <comanda>   (ex: help ip)")
            .addLine("Ca sa incepi:     load ssh assets/sample_ssh.log, apoi scan")
            .addLine("Log-uri de test:  python3 tools/loggen/loggen.py   (detalii: help generator)")
            .addLine("Liste incarcate:  whitelist " + std::to_string(whitelist_.size()) + ", blacklist " +
                     std::to_string(blacklist_.size()) + "   (whitelist.txt, blacklist.txt)");
        out_ << box;
    }

    void handleHelp(std::istream& in) const {
        std::istringstream args(restOfLine(in));
        std::string target;
        if (!(args >> target)) {
            ConsoleBox box;
            box.addTitle("LOGSENTINEL SIEM", "ajutor").addRule()
                .addLine("CE FACE")
                .addLine("Citeste log-uri de logare SSH si de firewall si cauta doua feluri de atac:")
                .addLine("  brute-force SSH  un IP ghiceste parole: multe incercari gresite, repede")
                .addLine("  port scan        un IP incearca multe porturi, ca sa vada ce servicii ai")
                .addLine("Cand acelasi IP le face pe amandoua, e un atac in doua etape (cel mai grav).")
                .addLine("Dupa scanare te ajuta sa reactionezi: blacklist si comenzi de blocare.")
                .addRule()
                .addLine("CUM INCEPI")
                .addLine("  1. load ssh assets/sample_ssh.log      incarci log-uri (si: load fw ...)")
                .addLine("  2. scan                                cauti atacuri")
                .addLine("  3. ip 198.51.100.23                    vezi tot ce a facut un IP")
                .addLine("  4. blacklist howto 198.51.100.23       afli cum il blochezi in firewall")
                .addRule();
            addCommandSections(box);
            box.addRule().addLine("GHIDURI");
            for (const HelpTopic& topic : helpTopics_) {
                std::ostringstream line;
                line << "  " << topic;
                box.addLine(line.str());
            }
            box.addLine("  help <comanda>     sintaxa si exemple pentru o comanda (ex: help scan)");
            out_ << box;
            return;
        }
        for (const HelpTopic& topic : helpTopics_) {
            if (topic.matches(target)) {
                topic.printFull(out_);
                return;
            }
        }
        const CommandInfo* found = findCommand(target);
        if (found == nullptr) {
            out_ << "Nu exista comanda sau ghidul '" << target << "'. Scrie 'help' ca sa le vezi pe toate.\n";
            return;
        }
        found->printDetails(out_);
    }

    void handleShow(std::istream& in) const {
        std::istringstream args(restOfLine(in));
        std::string type;
        int count = kDefaultShowCount;
        if (!(args >> type) || (type != "ssh" && type != "fw") || ((args >> count) && count <= 0)) {
            printUsage("show");
            return;
        }
        const bool ssh = type == "ssh";
        const int total = ssh ? sshSource_.getEntryCount() : fwSource_.getEntryCount();
        if (total == 0) {
            out_ << "Nu ai incarcat inca " << (ssh ? "log-uri SSH" : "pachete de firewall") << ". Foloseste 'load "
                 << type << " <fisier>' sau 'local " << type << " <minute>'.\n";
            return;
        }
        const int limit = count < total ? count : total;
        out_ << "Primele " << limit << " din " << total << (ssh ? " evenimente SSH:\n" : " pachete de firewall:\n");
        for (int i = 0; i < limit; i++) {
            if (ssh) {
                out_ << "  " << sshSource_.getEntryAt(i) << "\n";
            } else {
                out_ << "  " << fwSource_.getEntryAt(i) << "\n";
            }
        }
    }

    // dupa orice incarcare: totalul sursei si cum arata
    void printSshTotals() const {
        out_ << "In total ai " << sshSource_.getEntryCount() << " evenimente SSH:\n";
        sshSource_.printTelemetrySummary(out_);
    }

    void printFirewallTotals() const {
        out_ << "In total ai " << fwSource_.getEntryCount() << " pachete de firewall:\n";
        fwSource_.printTelemetrySummary(out_);
    }

    // "  blacklist howto 1.2.3.4                comanda de blocare in firewall" (descrierea pe aceeasi coloana)
    static std::string suggestion(const std::string& command, const std::string& description) {
        std::ostringstream line;
        line << "  " << std::left << std::setw(kSuggestionColumn) << command << description;
        return line.str();
    }

    static std::string lineCount(int count) { return std::to_string(count) + (count == 1 ? " linie" : " linii"); }

    // "12 valide, 1 respinsa" / "13 valide, 0 respinse"
    static std::string validRejected(int valid, int rejected) {
        return std::to_string(valid) + (valid == 1 ? " valida, " : " valide, ") + std::to_string(rejected) +
               (rejected == 1 ? " respinsa" : " respinse");
    }

    void handleSshIngestion(std::istream& in) {
        int count = 0;
        if (!(in >> count) || count <= 0) {
            printUsage("ingest-ssh");
            return;
        }
        const int added = sshSource_.ingestFromStream(in, count);
        out_ << "Am citit " << lineCount(count) << " SSH: " << validRejected(added, count - added) << ".\n";
        printSshTotals();
    }

    void handleFirewallIngestion(std::istream& in) {
        int count = 0;
        if (!(in >> count) || count <= 0) {
            printUsage("ingest-fw");
            return;
        }
        const int added = fwSource_.ingestFromStream(in, count);
        out_ << "Am citit " << lineCount(count) << " de firewall: " << validRejected(added, count - added) << ".\n";
        printFirewallTotals();
    }

    void handleFileIngestion(std::istream& in) {
        std::istringstream args(restOfLine(in));
        std::string type;
        std::string path;
        if (!(args >> type >> path) || (type != "ssh" && type != "fw")) {
            printUsage("load");
            return;
        }
        std::ifstream file(path);
        if (!file.is_open()) {
            out_ << "Nu pot deschide fisierul " << path << ". Verifica numele si ca rulezi din folderul potrivit.\n";
            return;
        }
        const bool ssh = type == "ssh";
        const int rejectedBefore = ssh ? sshSource_.getRejectedCount() : fwSource_.getRejectedCount();
        const int added = ssh ? sshSource_.ingestUntilEof(file) : fwSource_.ingestUntilEof(file);
        const int rejected = (ssh ? sshSource_.getRejectedCount() : fwSource_.getRejectedCount()) - rejectedBefore;
        if (added == 0) {
            out_ << "In " << path << " nu e nicio linie valida (" << lineCount(rejected) << " gresite).\n"
                 << "Formatul asteptat il vezi cu 'help logs'.\n";
            return;
        }
        out_ << "Am incarcat " << path << ": " << added << (ssh ? " evenimente SSH noi" : " pachete noi") << ", "
             << lineCount(rejected) << (rejected == 1 ? " respinsa.\n" : " respinse.\n");
        if (ssh) {
            printSshTotals();
        } else {
            printFirewallTotals();
        }
    }

    void handleLocalScan(std::istream& in) {
        std::string type;
        int minutes = 0;
        if (!(in >> type >> minutes) || (type != "ssh" && type != "fw") || minutes <= 0) {
            printUsage("local");
            return;
        }
        out_ << localCollector_ << "\n";
        const bool ssh = type == "ssh";
        const int added = ssh ? localCollector_.collectSsh(minutes, sshSource_, out_)
                              : localCollector_.collectFirewall(minutes, fwSource_, out_);
        if (added == 0) {
            return;
        }
        out_ << "Am adaugat " << added << (ssh ? " evenimente SSH reale" : " pachete reale") << " din ultimele "
             << minutes << " minute.\n";
        if (ssh) {
            printSshTotals();
        } else {
            printFirewallTotals();
        }
    }

    void handlePolicyUpdate(std::istream& in) {
        int sshThreshold = 0;
        int portThreshold = 0;
        int window = 0;
        double ratio = 0.0;
        if (!(in >> sshThreshold >> portThreshold >> window >> ratio)) {
            printUsage("policy");
            return;
        }
        const DetectionPolicy oldPolicy = analyzer_.getPolicy();
        if (!analyzer_.updatePolicy(DetectionPolicy(sshThreshold, portThreshold, window, ratio))) {
            out_ << "Valori imposibile: pragurile si fereastra trebuie sa fie mai mari ca 0, iar rata intre 0 si 1.\n"
                 << "Pragurile au ramas: " << analyzer_.getPolicy() << ".\n";
            return;
        }
        out_ << "Praguri noi:\n";
        analyzer_.getPolicy().printChangesFrom(out_, oldPolicy);
        out_ << "Se aplica la urmatorul 'scan'.\n";
    }

    bool handleFullScan() {
        if (sshSource_.getEntryCount() == 0 && fwSource_.getEntryCount() == 0) {
            out_ << "Nu am ce scana: nu ai incarcat inca log-uri. Incepe cu 'load ssh <fisier>' sau 'help logs'.\n";
            return false;
        }
        analyzer_.runFullSiemAnalysis();
        const int critical = analyzer_.countReported("CRITICAL");
        const int high = analyzer_.countReported("HIGH");
        const int medium = analyzer_.countReported("MEDIUM");
        ConsoleBox box;
        const int total = critical + high + medium;
        box.addTitle("RAPORT SCANARE", std::to_string(total) + (total == 1 ? " alerta" : " alerte")).addRule()
            .addLine("Date:      " + std::to_string(sshSource_.getEntryCount()) + " evenimente SSH, " +
                     std::to_string(fwSource_.getEntryCount()) + " pachete de firewall")
            .addLine("Gravitate: " + std::to_string(critical) + " CRITICAL, " + std::to_string(high) + " HIGH, " +
                     std::to_string(medium) + " MEDIUM");
        std::ostringstream policy;
        policy << "Praguri:   " << analyzer_.getPolicy();
        box.addLine(policy.str(), std::string("Praguri:   ").size());
        out_ << box << analyzer_;
        if (analyzer_.hasAnyAlerts()) {
            out_ << "Tot istoricul unui IP: ip <adresa>\n";
        }
        analyzer_.printActiveTrackers(out_);
        return true;
    }

    // dupa scan: IP-urile cu alerte HIGH/CRITICAL care nu sunt deja in vreo lista
    void offerBlacklist(std::istream& in) {
        std::vector<IpRange> targets;
        std::vector<std::string> reasons;
        const std::vector<Alert> dangerous = analyzer_.getHighRiskAlertsUniqueByIp();
        for (const Alert& alert : dangerous) {
            const Ipv4Address ip(alert.getIpString());
            if (!whitelist_.contains(ip) && !blacklist_.contains(ip)) {
                targets.emplace_back(alert.getIpString());
                reasons.push_back(alert.reason());
            }
        }
        if (targets.empty()) {
            if (!dangerous.empty()) {
                out_ << "\nIP-urile periculoase sunt deja in blacklist.\n";
            }
            return;
        }
        out_ << "\nIP-uri periculoase care nu sunt inca in blacklist:\n";
        confirmAndBlacklist(in, targets, reasons);
    }

    void offerSubnetEscalation(std::istream& in) {
        std::vector<IpRange> targets;
        std::vector<std::string> reasons;
        const std::vector<SubnetProposal> proposals = escalator_.propose(blacklist_, whitelist_);
        for (const SubnetProposal& proposal : proposals) {
            targets.push_back(proposal.getRange());
            reasons.push_back(proposal.evidenceText());
        }
        out_ << escalator_ << "\n";
        if (targets.empty()) {
            out_ << "Deocamdata nicio retea nu are destule IP-uri in blacklist ca sa merite blocata intreaga.\n";
            return;
        }
        out_ << "Retele care merita blocate intregi:\n";
        confirmAndBlacklist(in, targets, reasons);
    }

    // whitelist/blacklist add|remove|list (+ howto|export|escalate doar la blacklist)
    void handleIpListCommand(std::istream& in, IpList& list, const IpList& otherList, const std::string& keyword) {
        std::istringstream args(restOfLine(in));
        std::string action;
        std::string entry;
        if (!(args >> action)) {
            printUsage(keyword);
            return;
        }
        const bool isBlacklist = keyword == "blacklist";
        if (action == "list") {
            out_ << list << "\n";
            return;
        }
        if (isBlacklist && action == "escalate") {
            offerSubnetEscalation(in);
            return;
        }
        if (!(args >> entry)) {
            printUsage(keyword);
            return;
        }
        std::string reason;
        std::getline(args >> std::ws, reason);
        const IpRange range(entry);

        if (action == "add") {
            if (range.isValid() && otherList.overlaps(range)) {
                out_ << "Nu pot: " << range << " se suprapune cu " << (isBlacklist ? "whitelist" : "blacklist")
                     << ". Scoate-l intai de acolo cu '" << (isBlacklist ? "whitelist" : "blacklist") << " remove'.\n";
                return;
            }
            if (isBlacklist && range.networkAddress().isPrivate()) {
                out_ << "Atentie: " << range << " e o adresa din reteaua locala. Daca e calculatorul tau sau routerul,\n"
                     << "blocarea lui in firewall te poate deconecta.\n";
            }
            if (list.add(entry, reason, out_)) {
                out_ << (isBlacklist ? "La urmatorul 'scan', orice activitate a lui apare ca alerta.\n"
                                     : "Nu va mai aparea in alerte.\n");
            }
        } else if (action == "remove") {
            list.remove(entry, out_);
        } else if (isBlacklist && action == "howto") {
            out_ << FirewallBlockAdvisor(range);
        } else if (isBlacklist && action == "export") {
            list.exportBlockScript(entry, out_);
        } else {
            printUsage(keyword);
        }
    }

    void handleIpInvestigation(std::istream& in) const {
        std::string target;
        if (!(in >> target)) {
            printUsage("ip");
            return;
        }
        const Ipv4Address address(target);
        if (!address.isValid()) {
            out_ << "'" << target << "' nu e o adresa IPv4 valida (exemplu: 192.168.1.50).\n";
            return;
        }
        std::ostringstream sshLines;
        const int sshHits = sshSource_.printEntriesForIp(sshLines, target);
        std::ostringstream fwLines;
        const int fwHits = fwSource_.printPacketsForIp(fwLines, target);
        std::ostringstream alertLines;
        const int alertCount = analyzer_.printAlertsForIp(alertLines, target);
        std::string lists = "nu e in nicio lista";
        if (whitelist_.contains(address)) {
            lists = "in whitelist";
        } else if (blacklist_.contains(address)) {
            lists = "in blacklist";
        }

        ConsoleBox box;
        box.addTitle("IP " + target, lists).addRule()
            .addLine(std::to_string(sshHits) + " incercari SSH, " + std::to_string(fwHits) + " pachete de firewall, " +
                     std::to_string(alertCount) + " alerte la ultimul scan");
        if (sshHits > 0 && fwHits > 0) {
            box.addLine("Apare in ambele surse: pachete prin firewall si incercari de logare SSH.");
        }
        if (sshHits + fwHits == 0) {
            box.addLine("Adresa nu apare in log-urile incarcate.");
        } else if (alertCount == 0) {
            box.addLine("Nicio alerta (daca n-ai rulat 'scan' dupa ce ai incarcat log-urile, ruleaza-l acum).");
        }
        if (alertCount > 0 && !whitelist_.contains(address)) {
            box.addRule().addLine("CE POTI FACE");
            if (!blacklist_.contains(address)) {
                box.addLine(suggestion("blacklist add " + target + " <motiv>", "il marchezi ca rau"));
            }
            box.addLine(suggestion("blacklist howto " + target, "comanda de blocare in firewall"))
                .addLine(suggestion("whitelist add " + target + " <motiv>", "daca e de incredere"));
        }
        out_ << box;
        if (sshHits > 0) {
            out_ << "Incercari SSH:\n" << sshLines.str();
        }
        if (fwHits > 0) {
            out_ << "Pachete de firewall:\n" << fwLines.str();
        }
        if (alertCount > 0) {
            out_ << "Alerte:\n" << alertLines.str();
        }
    }

    // copia alertei originale (constructor de copiere) + versiunea escaladata (operator=)
    void handleAlertArchival() {
        if (!analyzer_.hasAnyAlerts()) {
            out_ << "Nu am ce arhiva: ruleaza intai 'scan', iar arhivarea ia cea mai grava alerta gasita.\n";
            return;
        }
        Alert current = analyzer_.getTopPriorityAlert();
        const Alert original(current);
        current = current.escalatedToTier2();
        archivedAlerts_.push_back(original);
        archivedAlerts_.push_back(current);
        out_ << "Am arhivat cel mai grav incident:\n" << original << "\n"
             << "si l-am marcat ca predat echipei Tier-2:\n" << current << "\n"
             << "Arhiva are acum " << archivedAlerts_.size() << " intrari ('status' le arata).\n";
    }

    void handleStatus() const {
        std::ostringstream ssh;
        ssh << sshSource_ << "\n";
        sshSource_.printTelemetrySummary(ssh);
        std::ostringstream fw;
        fw << fwSource_ << "\n";
        fwSource_.printTelemetrySummary(fw);
        std::ostringstream policy;
        policy << analyzer_.getPolicy();

        ConsoleBox box;
        box.addTitle("STARE", std::to_string(executedCommands_) + " comenzi, ultima: " + lastCommand_).addRule()
            .addLine("LOG-URI INCARCATE").addText(ssh.str()).addText(fw.str()).addRule()
            .addLine("PRAGURI").addLine(policy.str(), 2).addRule()
            .addLine("LISTE SI ARHIVA")
            .addLine("whitelist " + std::to_string(whitelist_.size()) + " intrari, blacklist " +
                     std::to_string(blacklist_.size()) + " intrari, arhiva " + std::to_string(archivedAlerts_.size()) +
                     " incidente");
        out_ << box;
        if (whitelist_.size() > 0) {
            out_ << whitelist_ << "\n";
        }
        if (blacklist_.size() > 0) {
            out_ << blacklist_ << "\n";
        }
        if (!archivedAlerts_.empty()) {
            out_ << "arhiva (" << archivedAlerts_.size() << "):\n";
            for (const Alert& alert : archivedAlerts_) {
                out_ << alert << "\n";
            }
        }
    }

    // trimite comanda la handler-ul ei; false = iesire
    bool dispatch(int option, std::istream& in) {
        switch (option) {
            case 0: out_ << "La revedere.\n"; return false;
            case 1: handleSshIngestion(in); break;
            case 2: handleFirewallIngestion(in); break;
            case 3: handlePolicyUpdate(in); break;
            case 4:
                if (handleFullScan()) {
                    offerBlacklist(in);
                }
                break;
            case 5: handleIpInvestigation(in); break;
            case 6: handleAlertArchival(); break;
            case 7: handleStatus(); break;
            case 8: handleFileIngestion(in); break;
            case 9: handleHelp(in); break;
            case 10: handleShow(in); break;
            case 11: handleLocalScan(in); break;
            case 12: handleIpListCommand(in, whitelist_, blacklist_, "whitelist"); break;
            case 13: handleIpListCommand(in, blacklist_, whitelist_, "blacklist"); break;
            default: break;
        }
        return true;
    }

public:
    SiemConsoleApp(std::ostream& out, const std::string& sshStreamName, const std::string& fwStreamName)
        : out_(out),
          sshSource_(sshStreamName),
          fwSource_(fwStreamName),
          whitelist_("whitelist", "whitelist.txt"),
          blacklist_("blacklist", "blacklist.txt"),
          analyzer_(sshSource_, fwSource_, whitelist_, blacklist_),
          escalator_(kMinBadIpsPer24, kMinBad24sPer16),
          localCollector_("logsentinel_local_export.txt"),
          executedCommands_(0),
          lastCommand_("niciuna") {
        registerCommands();
        whitelist_.load(out_);
        blacklist_.load(out_);
    }

    void run(std::istream& in) {
        printStartup();
        std::string token;
        while (true) {
            out_ << "\nlogsentinel> ";
            if (!(in >> token)) {
                out_ << "\nInputul s-a terminat, inchid aplicatia.\n";
                return;
            }
            const CommandInfo* cmd = findCommand(token);
            if (cmd == nullptr) {
                out_ << "Nu cunosc comanda '" << token << "'. Scrie 'help' ca sa vezi comenzile.\n";
                restOfLine(in);   // sarim restul liniei, ca argumentele ei sa nu fie luate drept comenzi
                continue;
            }
            executedCommands_++;
            lastCommand_ = cmd->getKeyword();
            if (!dispatch(cmd->getNumber(), in)) {
                return;
            }
        }
    }

    // rezumatul de la final (din main)
    friend std::ostream& operator<<(std::ostream& os, const SiemConsoleApp& app) {
        return os << "Sesiune: " << app.executedCommands_ << " comenzi, " << app.archivedAlerts_.size()
                  << " incidente arhivate. " << app.sshSource_ << "; " << app.fwSource_ << ".";
    }
};

#endif
