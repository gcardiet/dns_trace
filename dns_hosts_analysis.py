import pyshark,pythonwhois
import sys,os,socket,time,argparse,logging,textwrap

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

dns_servers = []
dns_servers_error = []
dns_servers_valid = []

def analyse_data(file):
    """
    Parse all arguments and call the subsequent functions of the program
    """
    global dns_servers

    # Live capture
    #cap = pyshark.LiveCapture(interface='en0', bpf_filter='udp port 53')

    # Get file capture and analyse the data
    cap = pyshark.FileCapture(file)
    cap.apply_on_packets(print_hosts_info, timeout=100)

    # Getting the raw results
    print ("------------------------------")
    print ("Listing the full trace details")
    print ("------------------------------")
    for dns_server in dns_servers:
        print ("Server: " + dns_server + " - Occurences: " + str(dns_servers.count(dns_server)))

    print ("---------------------------------------------------")
    print ("Trying to resolve the names and removing duplicates")
    print ("---------------------------------------------------")
    dns_servers = sorted(set(dns_servers))
    for dns_server in dns_servers:
        try:
            print ("Server: " + dns_server + " - IP: " + socket.gethostbyname(dns_server))
            dns_servers_valid.append(dns_server)

        except socket.error:
            print ("Server: " + dns_server + " - does not resolve")
            dns_servers_error.append(dns_server)

    print ("----------------------------")
    print ("Summary of the network trace")
    print ("----------------------------")
    print ('Number of DNS server found in the trace: ' +  str(len(dns_servers)))
    print ("Number of servers reachable: " + str(len(dns_servers_valid)))
    print ("Number of servers unreachable: " + str(len(dns_servers_error)))

    for dns_server_valid in dns_servers_valid:
        details = pythonwhois.get_whois(dns_server_valid)
        print (details['contacts']['registrant'])
        time.sleep(5)
        #print(details)

def print_hosts_info(pkt):
    """
    Parse all arguments and call the subsequent functions of the program
    """
    global dns_servers
    if pkt.dns.qry_name:
        dns_servers.append(pkt.dns.qry_name)

def main():
    """
    Parse all arguments and call the subsequent functions of the program
    """
    parser = argparse.ArgumentParser(description='Triggers some of the Vectra detections')
    parser = argparse.ArgumentParser(prog='PROG', formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''\
            This script analyse a network trace and extract DNS
            ---------------------------------------------------
            This script looks at all DNS entries and find the names.
            Once the data will be retrieved, I woud look if the server still exists.
            '''))
    parser.add_argument('-f','--file', nargs=1, help='PCAP file with DNS requests to parse', action='store')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()

    if (args.file):
        analyse_data (args.file[0])
        return

    parser.print_help()

if __name__ == "__main__":
    main()
