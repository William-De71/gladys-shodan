// -----------------------------------------------------------------------------
// Texts of the Shodan integration, in English, French, German and Spanish
// (English fallback).
//
// The manifest carries its own labels; these are the texts the code writes at
// runtime: feature names, widget contents, scene texts, errors, results of the
// configuration buttons. Vocabulary of the Gladys interface (appareil / Gerät
// / dispositivo). German says "du", Spanish "usted", like Gladys. A key
// ending in `_one` / `_other` is a plural (tn() in i18n.js).
// -----------------------------------------------------------------------------

const TEXTS = {
  // devices
  namePublic: {
    en: 'Shodan: public IP',
    fr: 'Shodan : IP publique',
    de: 'Shodan: öffentliche IP',
    es: 'Shodan: IP pública',
  },
  feature_open_ports: {
    en: 'Open ports',
    fr: 'Ports ouverts',
    de: 'Offene Ports',
    es: 'Puertos abiertos',
  },
  feature_vulnerabilities: {
    en: 'Vulnerabilities',
    fr: 'Vulnérabilités',
    de: 'Schwachstellen',
    es: 'Vulnerabilidades',
  },
  feature_ip: { en: 'IP address', fr: 'Adresse IP', de: 'IP-Adresse', es: 'Dirección IP' },
  feature_ports: {
    en: 'Exposed ports',
    fr: 'Ports exposés',
    de: 'Erreichbare Ports',
    es: 'Puertos expuestos',
  },
  noPorts: {
    en: 'none seen',
    fr: 'aucun vu',
    de: 'keiner gesehen',
    es: 'ninguno visto',
  },

  // times
  never: { en: 'never', fr: 'jamais', de: 'nie', es: 'nunca' },
  justNow: { en: 'just now', fr: 'à l’instant', de: 'gerade eben', es: 'ahora mismo' },
  minutesAgo: { en: '{n} min ago', fr: 'il y a {n} min', de: 'vor {n} Min.', es: 'hace {n} min' },
  hoursAgo: { en: '{n} h ago', fr: 'il y a {n} h', de: 'vor {n} Std.', es: 'hace {n} h' },
  daysAgo: { en: '{n} d ago', fr: 'il y a {n} j', de: 'vor {n} T.', es: 'hace {n} d' },

  // widgets
  badgeError: { en: 'Error', fr: 'Erreur', de: 'Fehler', es: 'Error' },
  badgeWaiting: { en: 'Waiting', fr: 'En attente', de: 'Wartet', es: 'En espera' },
  badgeNothing: { en: 'Nothing seen', fr: 'Rien de vu', de: 'Nichts gesehen', es: 'Nada visto' },
  badgeVulns_one: { en: '{count} CVE', fr: '{count} CVE', de: '{count} CVE', es: '{count} CVE' },
  badgeVulns_other: { en: '{count} CVE', fr: '{count} CVE', de: '{count} CVE', es: '{count} CVE' },
  badgePorts_one: {
    en: '{count} port',
    fr: '{count} port',
    de: '{count} Port',
    es: '{count} puerto',
  },
  badgePorts_other: {
    en: '{count} ports',
    fr: '{count} ports',
    de: '{count} Ports',
    es: '{count} puertos',
  },
  portsShort_one: {
    en: '{count} port',
    fr: '{count} port',
    de: '{count} Port',
    es: '{count} puerto',
  },
  portsShort_other: {
    en: '{count} ports',
    fr: '{count} ports',
    de: '{count} Ports',
    es: '{count} puertos',
  },
  vulnsShort_one: { en: '{count} CVE', fr: '{count} CVE', de: '{count} CVE', es: '{count} CVE' },
  vulnsShort_other: { en: '{count} CVE', fr: '{count} CVE', de: '{count} CVE', es: '{count} CVE' },
  tilePorts: { en: 'Open ports', fr: 'Ports ouverts', de: 'Offene Ports', es: 'Puertos abiertos' },
  tileVulns: {
    en: 'Vulnerabilities',
    fr: 'Vulnérabilités',
    de: 'Schwachstellen',
    es: 'CVE conocidas',
  },
  tileCvss: { en: 'Highest CVSS', fr: 'CVSS maximal', de: 'Höchster CVSS', es: 'CVSS máximo' },
  tileQueryCredits: { en: 'Query credits', fr: 'Requêtes', de: 'Abfragen', es: 'Consultas' },
  tileScanCredits: {
    en: 'Scan credits',
    fr: 'Crédits de scan',
    de: 'Scan-Credits',
    es: 'Escaneos',
  },
  tileMonitored: {
    en: 'Monitored IPs',
    fr: 'IP surveillées',
    de: 'Überwachte IPs',
    es: 'IP vigiladas',
  },
  captionInternetDb: {
    en: 'Source: Shodan InternetDB, refreshed weekly',
    fr: 'Source : Shodan InternetDB, hebdomadaire',
    de: 'Quelle: Shodan InternetDB, wöchentlich',
    es: 'Fuente: Shodan InternetDB, semanal',
  },
  captionApi: {
    en: 'Source: Shodan API',
    fr: 'Source : API Shodan',
    de: 'Quelle: Shodan-API',
    es: 'Fuente: API de Shodan',
  },
  unknownService: {
    en: 'Unknown service',
    fr: 'Service inconnu',
    de: 'Unbekannter Dienst',
    es: 'Servicio desconocido',
  },
  openPort: { en: 'Open port', fr: 'Port ouvert', de: 'Offener Port', es: 'Puerto abierto' },
  bodyVulns: {
    en: 'Vulnerabilities matched to the software seen (not verified): {list}',
    fr: 'Vulnérabilités associées aux logiciels vus (non vérifiées) : {list}',
    de: 'Schwachstellen zur gesehenen Software (nicht geprüft): {list}',
    es: 'Vulnerabilidades asociadas al software visto (no verificadas): {list}',
  },
  bodyNoVulns: {
    en: 'No known vulnerability matched to the software seen. Close what does not need to be reachable from the Internet.',
    fr: 'Aucune vulnérabilité connue pour les logiciels vus. Fermez ce qui n’a pas besoin d’être joignable depuis Internet.',
    de: 'Keine bekannte Schwachstelle zur gesehenen Software. Schließe, was nicht aus dem Internet erreichbar sein muss.',
    es: 'Ninguna vulnerabilidad conocida para el software visto. Cierre lo que no necesite ser accesible desde Internet.',
  },
  bodyNothing: {
    en: 'Shodan sees no open port on this address.',
    fr: 'Shodan ne voit aucun port ouvert sur cette adresse.',
    de: 'Shodan sieht keinen offenen Port an dieser Adresse.',
    es: 'Shodan no ve ningún puerto abierto en esta dirección.',
  },
  rowPorts: { en: 'Ports', fr: 'Ports', de: 'Ports', es: 'Puertos' },
  rowVulns: {
    en: 'Vulnerabilities',
    fr: 'Vulnérabilités',
    de: 'Schwachstellen',
    es: 'Vulnerabilidades',
  },
  rowTags: {
    en: 'Shodan tags',
    fr: 'Étiquettes Shodan',
    de: 'Shodan-Tags',
    es: 'Etiquetas Shodan',
  },
  rowIp: { en: 'IP address', fr: 'Adresse IP', de: 'IP-Adresse', es: 'Dirección IP' },
  rowLastScan: {
    en: 'Last seen by Shodan',
    fr: 'Vue par Shodan',
    de: 'Von Shodan gesehen',
    es: 'Vista por Shodan',
  },
  rowRead: { en: 'Read', fr: 'Lu', de: 'Gelesen', es: 'Leído' },
  rowHostnames: { en: 'Host names', fr: 'Noms d’hôte', de: 'Hostnamen', es: 'Nombres de host' },
  rowOrg: { en: 'Network', fr: 'Réseau', de: 'Netz', es: 'Red' },
  rowSource: { en: 'Source', fr: 'Source', de: 'Quelle', es: 'Fuente' },
  rowPlan: { en: 'Plan', fr: 'Offre', de: 'Tarif', es: 'Plan' },
  rowScan: { en: 'Scan {ip}', fr: 'Scan {ip}', de: 'Scan {ip}', es: 'Escaneo {ip}' },
  rowAgo: {
    en: '{time} ({ago})',
    fr: '{time} ({ago})',
    de: '{time} ({ago})',
    es: '{time} ({ago})',
  },
  sourceInternetDb: {
    en: 'InternetDB (weekly)',
    fr: 'InternetDB (hebdomadaire)',
    de: 'InternetDB (wöchentlich)',
    es: 'InternetDB (semanal)',
  },
  sourceApi: { en: 'Shodan API', fr: 'API Shodan', de: 'Shodan-API', es: 'API de Shodan' },
  scan_SUBMITTING: { en: 'Sent', fr: 'Envoyé', de: 'Gesendet', es: 'Enviado' },
  scan_QUEUE: { en: 'Queued', fr: 'En file', de: 'In der Warteschlange', es: 'En cola' },
  scan_PROCESSING: { en: 'Scanning', fr: 'En cours', de: 'Läuft', es: 'En curso' },
  scan_DONE: { en: 'Done', fr: 'Terminé', de: 'Fertig', es: 'Terminado' },
  scan_FAILED: { en: 'Failed', fr: 'Échec', de: 'Fehlgeschlagen', es: 'Fallido' },
  buttonRefresh: { en: 'Read again', fr: 'Relire', de: 'Neu lesen', es: 'Volver a leer' },
  linkShodan: {
    en: 'Open on Shodan',
    fr: 'Voir sur Shodan',
    de: 'Auf Shodan öffnen',
    es: 'Ver en Shodan',
  },
  toastRefreshed: {
    en: 'Read again: {count} port(s), {vulns} vulnerability(ies).',
    fr: 'Relu : {count} port(s), {vulns} vulnérabilité(s).',
    de: 'Neu gelesen: {count} Port(s), {vulns} Schwachstelle(n).',
    es: 'Leído de nuevo: {count} puerto(s), {vulns} vulnerabilidad(es).',
  },
  toastTooSoon: {
    en: 'Already read less than a minute ago.',
    fr: 'Déjà lu il y a moins d’une minute.',
    de: 'Vor weniger als einer Minute schon gelesen.',
    es: 'Ya leído hace menos de un minuto.',
  },

  // scene texts
  summaryNothing: {
    en: '{who}: Shodan sees no open port.',
    fr: '{who} : Shodan ne voit aucun port ouvert.',
    de: '{who}: Shodan sieht keinen offenen Port.',
    es: '{who}: Shodan no ve ningún puerto abierto.',
  },
  summaryPorts_one: {
    en: '{who}: {count} open port ({ports}),',
    fr: '{who} : {count} port ouvert ({ports}),',
    de: '{who}: {count} offener Port ({ports}),',
    es: '{who}: {count} puerto abierto ({ports}),',
  },
  summaryPorts_other: {
    en: '{who}: {count} open ports ({ports}),',
    fr: '{who} : {count} ports ouverts ({ports}),',
    de: '{who}: {count} offene Ports ({ports}),',
    es: '{who}: {count} puertos abiertos ({ports}),',
  },
  summaryVulns_one: {
    en: '{count} vulnerability{max}.',
    fr: '{count} vulnérabilité{max}.',
    de: '{count} Schwachstelle{max}.',
    es: '{count} vulnerabilidad{max}.',
  },
  summaryVulns_other: {
    en: '{count} vulnerabilities{max}.',
    fr: '{count} vulnérabilités{max}.',
    de: '{count} Schwachstellen{max}.',
    es: '{count} vulnerabilidades{max}.',
  },
  summaryNoVulns: {
    en: 'no known vulnerability.',
    fr: 'aucune vulnérabilité connue.',
    de: 'keine bekannte Schwachstelle.',
    es: 'ninguna vulnerabilidad conocida.',
  },
  summaryTags: {
    en: 'Shodan tags: {tags}.',
    fr: 'Étiquettes Shodan : {tags}.',
    de: 'Shodan-Tags: {tags}.',
    es: 'Etiquetas Shodan: {tags}.',
  },

  // connection status
  statusNoTarget: {
    en: 'Nothing to watch: turn on the public address or type an address.',
    fr: 'Rien à surveiller : activez l’adresse publique ou saisissez une adresse.',
    de: 'Nichts zu überwachen: Aktiviere die öffentliche Adresse oder gib eine Adresse ein.',
    es: 'Nada que vigilar: active la dirección pública o escriba una dirección.',
  },
  statusWaiting: {
    en: 'Waiting for the first reading of Shodan.',
    fr: 'En attente de la première lecture de Shodan.',
    de: 'Warte auf die erste Abfrage bei Shodan.',
    es: 'Esperando la primera lectura de Shodan.',
  },
  statusOk_one: {
    en: '1 address watched: {ports} open port(s), {vulns} vulnerability(ies).',
    fr: '1 adresse surveillée : {ports} port(s) ouvert(s), {vulns} vulnérabilité(s).',
    de: '1 Adresse überwacht: {ports} offene(r) Port(s), {vulns} Schwachstelle(n).',
    es: '1 dirección vigilada: {ports} puerto(s) abierto(s), {vulns} vulnerabilidad(es).',
  },
  statusOk_other: {
    en: '{count} addresses watched: {ports} open port(s), {vulns} vulnerability(ies).',
    fr: '{count} adresses surveillées : {ports} port(s) ouvert(s), {vulns} vulnérabilité(s).',
    de: '{count} Adressen überwacht: {ports} offene(r) Port(s), {vulns} Schwachstelle(n).',
    es: '{count} direcciones vigiladas: {ports} puerto(s) abierto(s), {vulns} vulnerabilidad(es).',
  },
  statusKeyFallback: {
    en: 'API key refused: InternetDB (no key) answers meanwhile.',
    fr: 'Clé API refusée : InternetDB (sans clé) répond en attendant.',
    de: 'API-Schlüssel abgelehnt: InternetDB (ohne Schlüssel) antwortet solange.',
    es: 'Clave API rechazada: InternetDB (sin clave) responde mientras tanto.',
  },
  statusPaused: {
    en: 'Shodan paused after errors.',
    fr: 'Shodan en pause après des erreurs.',
    de: 'Shodan nach Fehlern pausiert.',
    es: 'Shodan en pausa tras errores.',
  },
  statusRejected: {
    en: 'Ignored (private or invalid): {list}.',
    fr: 'Ignorées (privées ou invalides) : {list}.',
    de: 'Ignoriert (privat oder ungültig): {list}.',
    es: 'Ignoradas (privadas o no válidas): {list}.',
  },

  // errors
  errAuth: {
    en: 'Shodan refuses the API key: check it on account.shodan.io.',
    fr: 'Shodan refuse la clé API : vérifiez-la sur account.shodan.io.',
    de: 'Shodan lehnt den API-Schlüssel ab: Prüfe ihn auf account.shodan.io.',
    es: 'Shodan rechaza la clave API: compruébela en account.shodan.io.',
  },
  errPlan: {
    en: 'The Shodan plan of this key does not allow it ({detail}).',
    fr: 'L’offre Shodan de cette clé ne le permet pas ({detail}).',
    de: 'Der Shodan-Tarif dieses Schlüssels erlaubt das nicht ({detail}).',
    es: 'El plan de Shodan de esta clave no lo permite ({detail}).',
  },
  errInvalid: {
    en: 'Shodan refuses this address: only public addresses can be looked up.',
    fr: 'Shodan refuse cette adresse : seules les adresses publiques peuvent être consultées.',
    de: 'Shodan lehnt diese Adresse ab: Nur öffentliche Adressen können abgefragt werden.',
    es: 'Shodan rechaza esta dirección: solo se pueden consultar direcciones públicas.',
  },
  errPaused: {
    en: 'Shodan is paused after errors: the next try is in a few minutes.',
    fr: 'Shodan est en pause après des erreurs : nouvel essai dans quelques minutes.',
    de: 'Shodan pausiert nach Fehlern: Der nächste Versuch folgt in einigen Minuten.',
    es: 'Shodan está en pausa tras errores: nuevo intento en unos minutos.',
  },
  errServer: {
    en: 'Shodan answers with an error: the next try is in a few minutes.',
    fr: 'Shodan répond par une erreur : nouvel essai dans quelques minutes.',
    de: 'Shodan antwortet mit einem Fehler: Der nächste Versuch folgt in einigen Minuten.',
    es: 'Shodan responde con un error: nuevo intento en unos minutos.',
  },
  errUnreachable: {
    en: 'Shodan cannot be reached: check the Internet access of Gladys.',
    fr: 'Shodan est injoignable : vérifiez l’accès Internet de Gladys.',
    de: 'Shodan ist nicht erreichbar: Prüfe den Internetzugang von Gladys.',
    es: 'Shodan no responde: compruebe el acceso a Internet de Gladys.',
  },
  errFailed: {
    en: 'Shodan reading failed: {detail}',
    fr: 'Échec de la lecture Shodan : {detail}',
    de: 'Shodan-Abfrage fehlgeschlagen: {detail}',
    es: 'Error de la lectura de Shodan: {detail}',
  },
  errDns: {
    en: '{host} does not resolve to a public address.',
    fr: '{host} ne correspond à aucune adresse publique.',
    de: '{host} ergibt keine öffentliche Adresse.',
    es: '{host} no corresponde a ninguna dirección pública.',
  },
  errAddress: {
    en: '“{address}” is not a public IP address nor a host name.',
    fr: '« {address} » n’est ni une adresse IP publique ni un nom d’hôte.',
    de: '„{address}“ ist weder eine öffentliche IP-Adresse noch ein Hostname.',
    es: '«{address}» no es una dirección IP pública ni un nombre de host.',
  },
  errNoKey: {
    en: 'This needs a Shodan API key (Configuration of the integration).',
    fr: 'Il faut une clé API Shodan (configuration de l’intégration).',
    de: 'Dafür braucht es einen Shodan-API-Schlüssel (Konfiguration der Integration).',
    es: 'Se necesita una clave API de Shodan (configuración de la integración).',
  },
  errNoTarget: {
    en: 'No address read yet.',
    fr: 'Aucune adresse lue pour l’instant.',
    de: 'Noch keine Adresse gelesen.',
    es: 'Todavía no se ha leído ninguna dirección.',
  },
  errNoPublicIp: {
    en: 'The public address is not known yet.',
    fr: 'L’adresse publique n’est pas encore connue.',
    de: 'Die öffentliche Adresse ist noch nicht bekannt.',
    es: 'La dirección pública aún no se conoce.',
  },

  // configuration buttons
  testOk: {
    en: 'Shodan answers. Public address: {ip}. {count} address(es) read with {source}.{plan}',
    fr: 'Shodan répond. Adresse publique : {ip}. {count} adresse(s) lue(s) avec {source}.{plan}',
    de: 'Shodan antwortet. Öffentliche Adresse: {ip}. {count} Adresse(n) gelesen mit {source}.{plan}',
    es: 'Shodan responde. Dirección pública: {ip}. {count} dirección(es) leída(s) con {source}.{plan}',
  },
  testPlan: {
    en: ' Plan: {plan}, {credits} scan credit(s).',
    fr: ' Offre : {plan}, {credits} crédit(s) de scan.',
    de: ' Tarif: {plan}, {credits} Scan-Credit(s).',
    es: ' Plan: {plan}, {credits} crédito(s) de escaneo.',
  },
  diagnosticDone: {
    en: 'Diagnostic written to the logs of the integration ({count} line(s)).',
    fr: 'Diagnostic écrit dans les journaux de l’intégration ({count} ligne(s)).',
    de: 'Diagnose in die Logs der Integration geschrieben ({count} Zeile(n)).',
    es: 'Diagnóstico escrito en los registros de la integración ({count} línea(s)).',
  },
};

export { TEXTS };
