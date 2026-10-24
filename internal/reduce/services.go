package reduce

import "strings"

// The rules that make a service a finding, by nmap service name, by a word in nmap's product, or, when
// nmap did not identify the service, by the well-known port. A port matches at most one of them.
var (
	// datastore: databases, caches, search engines and message queues, which hold or move data and are
	// often reachable without credentials.
	datastoreServices = words(`mysql postgresql redis mongodb mongod ms-sql-s ms-sql-m oracle oracle-tns memcached
		elasticsearch cassandra couchdb riak rethinkdb neo4j influxdb zookeeper kafka amqp rabbitmq mqtt nats
		clickhouse db2 ibm-db2 drda sybase gds_db hbase solr`)
	datastoreProducts = []string{"elasticsearch", "opensearch", "mongodb", "couchdb", "redis", "memcached", "clickhouse",
		"influxdb", "rabbitmq", "apache solr", "cassandra", "neo4j", "mysql", "mariadb", "postgresql", "minio"}

	// admin-api: APIs and consoles that control infrastructure or run code: the Docker and Kubernetes
	// APIs, etcd, CI servers, service discovery, notebooks and Java debug ports.
	adminServices = words(`docker kubernetes kubelet etcd etcd-client etcd-server jdwp java-rmi rmiregistry consul`)
	adminProducts = []string{"docker", "kubernetes", "kubelet", "etcd", "jenkins", "consul", "nomad", "portainer",
		"jupyter", "kibana", "rancher", "hadoop", "spark", "java debug wire protocol"}

	// remote-admin: interactive remote access: RDP, VNC, Telnet, SMB, WinRM, X11, the r-services, and SSH on
	// any port but 22 (SSH on 22 is expected and goes to a group).
	remoteServices = words(`ms-wbt-server vnc vnc-http telnet microsoft-ds netbios-ssn x11 login shell exec wsman
		wsmans winrm`)

	// file-share: FTP, TFTP, NFS and its portmapper, rsync and AFP.
	fileServices = words(`ftp tftp nfs rpcbind rsync afp afpovertcp`)
)

// wellKnown names the service a port usually runs, for when nmap did not run or could not tell. The
// name is written with a "?" after it: it is a guess from the number, not an identification.
var wellKnown = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 69: "tftp", 80: "http", 110: "pop3",
	111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds",
	465: "smtps", 512: "exec", 513: "login", 514: "shell", 548: "afp", 587: "submission", 623: "ipmi",
	636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1099: "java-rmi", 1433: "ms-sql-s", 1521: "oracle-tns",
	1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker", 2379: "etcd", 2380: "etcd",
	3000: "http", 3306: "mysql", 3389: "ms-wbt-server", 4646: "nomad", 5000: "http", 5432: "postgresql",
	5672: "amqp", 5900: "vnc", 5901: "vnc", 5902: "vnc", 5903: "vnc", 5984: "couchdb", 5985: "wsman",
	5986: "wsmans", 6000: "x11", 6379: "redis", 6443: "kubernetes", 7474: "neo4j", 8000: "http", 8080: "http",
	8086: "influxdb", 8123: "clickhouse", 8443: "https", 8500: "consul", 8888: "http", 9042: "cassandra",
	9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch", 10250: "kubelet", 10255: "kubelet",
	11211: "memcached", 15672: "rabbitmq", 27017: "mongodb", 28015: "rethinkdb",
}

// Category returns the rule a service matches ("datastore", "admin-api", "remote-admin", "file-share"),
// or "". service is nmap's name, with "ssl/" and a trailing "?" allowed.
func Category(service, product string, port int) string {
	name := strings.TrimSuffix(strings.TrimPrefix(service, "ssl/"), "?")
	p := strings.ToLower(product)
	switch {
	case containsAny(p, adminProducts) || adminServices[name]:
		return "admin-api"
	case containsAny(p, datastoreProducts) || datastoreServices[name]:
		return "datastore"
	case name == "ssh" && port != 22, remoteServices[name]:
		return "remote-admin"
	case fileServices[name]:
		return "file-share"
	}
	return ""
}

// Guess is the well-known service of a port, with "?" after it, or "" when the port has none.
func Guess(port int, protocol string) string {
	if protocol == "udp" {
		switch port {
		case 53:
			return "domain?"
		case 69:
			return "tftp?"
		case 161:
			return "snmp?"
		case 623:
			return "ipmi?"
		}
		return ""
	}
	if s, ok := wellKnown[port]; ok {
		return s + "?"
	}
	return ""
}

// identified is false when nmap gave no service, or a name that is not an identification.
func identified(service string) bool {
	name := strings.TrimPrefix(service, "ssl/")
	return name != "" && name != "unknown" && name != "tcpwrapped" && !strings.HasSuffix(name, "?")
}

func containsAny(s string, subs []string) bool {
	if s == "" {
		return false
	}
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}
