import sys
import nmap
import optparse
#sys.path.append("C:\Users\asingh\Documents\GitHub\ViolentPython\Scripts")
from Args import *

def nmapScan(tgtHost, tgtPort):
    nmSacan = nmap.PortScanner()
    nmScan.scan(tgtHost, tgtPort)
    state = nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
    print ' [*] ' + tgtHost + ' tcp/' + tgtPort + ' ' + state

def main():
    args = Args({'-H': 'alpha', '-p': 'omega' })
    argsResult = args.getArgs()
    print argsResult.alpha
        
if __name__ == "__main__":
    main()
