import nmap,argparse,sys
class INFO:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
def get_args():
    parger = argparse.ArgumentParser(description='port scan script')
    parger.add_argument('-H', '--host', help='specify target host')
    parger.add_argument('-P', '--port', help='specify target port')
    args = parger.parse_args()
    if args.host == None:
        parger.error('host is required')
        sys.exit()
    if args.port == None:
        parger.error('port is required')
        sys.exit()
    else:
        return args


def scan_port(host, port):
    nm = nmap.PortScanner()
    try:
        result= nm.scan(host,port)
        print result
        state = result['scan'][host]['tcp'][int(port)]['state']
        if state == 'open':
            print INFO.OKBLUE+'[*] '+host+ ' tcp/'+port+" "+state+INFO.ENDC
        else:
            print INFO.WARNING + '[*] ' + host + ' tcp/' + port + " " + state + INFO.ENDC
    except Exception,e:
        raise e
        
    
    

if __name__ == '__main__':
    args = get_args()
    if '-' in args.port:
        ports_list = args.port.split('-')
        for p in range(int(ports_list[0]),int(ports_list[1])+1):
            scan_port(args.host, str(p))
    else:
        ports_list = args.port.split(',')
        for p in ports_list:
            scan_port(args.host, p)
            
        