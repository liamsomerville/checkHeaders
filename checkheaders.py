'''
 Original Author ToddBenson, Modified by Liam Somerville
 https://github.com/ToddBenson
 https://github.com/ToddBenson/checkHeaders/blob/master/checkheaders.py

This script peforms the following header checks
- cache contorl
- prgma
- content type
- content character set
- access control allow origin
- string transport security
- access-control-allow-origin
- X-Content-Type-Options
- x-content-security
- x-download-options
- x-powered-by
- server
- Ciphers

Usuage python HTTPSchecks.py http://www.google.com


******************************************************
NOTE: The script requires nmap to identify SSL Ciphers
******************************************************
'''

from urllib import urlopen
import urllib2
import sys

def main():

    if len(sys.argv) < 2:
        print
        print('Please provide a fully-qualified path!\n')
        print('Usage: python gethead.py path\n')
        print('Example: python gethead.py http://www.google.com\n\n')
        sys.exit()
    else:
        response = urllib2.urlopen(sys.argv[1])
        print
        print('HTTP Header Analysis for ' + sys.argv[1] + ':' + '\n\n')

    if len(sys.argv) == 3:
        if sys.argv[2] == "-h":
            print("Header:")
            print(urlopen(sys.argv[1]).info())
    print('=========================================')
    print("Checking for security headers...")
    print('=========================================')


    # Check for cache-control
    if response.info().getheader('cache-control'):
	if 'no-cache' and 'no-store' in response.info().getheader('cache-control'):
        	print('Cache-Control\t\t\t\t\tOK\t\t Cache-control is enabled.')
    	else:
        	print('Cache-Control\t\t\t\t\tCheck\t\t Check cache-control.')
    else:
	 print('Cache-Control\t\t\t\t\tCheck\t\t Cache-control is not enabled.')

    #Check pragma
    if response.info().getheader('pragma') == 'no-cache':
        print('Pragma\t\t\t\t\t\tOK\t\t pragma was set properly.')
        print '    Value returned:', response.info().getheader('pragma')
    else:
        print ('Pragma\t\t\t\t\t\tCheck\t\t pragma was not set.')
        print '    Value returned:', response.info().getheader('pragma')

    #Check for content-type
    if 'text/html' in response.info().getheader('content-type'):
        print ('Content-Type\t\t\t\t\tOK\t\t content-type was set to text/html.')
        print '    Value returned:', response.info().getheader('content-type')
    else:
        print ('Content-Type\t\t\t\t\tCheck\t\t content-type was not set to text/html.')
        print '    Header Missing!'
        
    #Check for content-type charset
    if 'charset=' in response.info().getheader('content-type'):
        print('Charset\t\t\t\t\t\tOK\t\t content-type charset was set.')
        print '    Value returned:', response.info().getheader('content-type')
    else:
        print('Charset\t\t\t\t\t\tCheck\t\t Charset was not set')
        print '    Header Missing!'
        
    # check access-control-allow-origin:
    if response.info().getheader('access-control-allow-origin'):
        print('Access-Control-Allow-Origin\t\t\tOK\t\tAccess Control Policies are enforced.')
        print '    Value returned:', response.info().getheader('access-control-allow-origin')
    else:
        print('Access-Control-Allow-Origins\t\t\tCheck\t\t Access Control Policies are not enforced.')
        print '    Header Missing!'

    # Check for strict-transport-security
    if response.info().getheader('strict-transport-security'):
        print('Strict-Transport-Security\t\t\tOK\t\t HTTP over TLS/SSL is enforced.')
        print '    Value returned:', response.info().getheader('strict-transport-security')
    else:
        print('Strict-Transport-Security\t\t\tCheck\t\t HTTP over TLS/SSL is not enforced.')
        print '    Header Missing!'
   
    #X-Content-Type-Options
    if response.info().getheader('x-content-type-options') == 'nosniff':
        print('X-Content-Type-Options\t\t\t\tOK\t\t x-content-type-options was set properly.')
        print '    Value returned:', response.info().getheader('x-content-type-options')
    else:
        print('X-Content-Type-Options\t\t\t\tCheck\t\t x-content-type-options was not set.')
        print '    Value returned:', response.info().getheader('x-content-type-options')
        
    #x-content-security
    if response.info().getheader('x-content-security-policy'):
        print('X-Content-Security-Policy\t\t\tOK\t\t Content Security Policy is enforced.')
        print '    Value returned:', response.info().getheader('x-content-security-policy')
    else:
        print('X-Content-Security-Policy\t\t\tCheck\t\t Content Security Policy is not enforced.')
        print '    Header Missing!'
        #print '    Value returned:', response.info().getheader('x-content-security-policy')

    # check x-download-options:
    if response.info().getheader('x-download-options') == 'noopen':
        print('X-Download-Options\t\t\t\tOK\t\t File Download and Open Restriction Policies are enforced.')
        print '    Value returned:', response.info().getheader('x-download-options')
    else:
        print('X-Download-Options\t\t\t\tCheck\t\t File Download and Open Restriction Policies are not enforced.')
        print '    Value returned:', response.info().getheader('x-download-options')
        
    # check x-xss-protection:
    if response.info().getheader('x-xss-protection') == '1; mode=block':
        print('X-XSS-Protection\t\t\t\tOK\t\t Cross-Site Scripting Protection is enforced.')
        print '    Value returned:', response.info().getheader('x-xss-protection')
    else:
        print('X-XSS-Protection\t\t\t\tCheck\t\t Cross-Site Scripting Protection was not enable or was not set properly.')
        print '    Value returned:', response.info().getheader('x-xss-protection')
    # Check for x-frame-options
    if response.info().getheader('x-frame-options'):
    	if response.info().getheader('x-frame-options').lower() == 'deny' or 'sameorigin':
          print("X-Frame-Options\t\t\t\t\tOK\t\t Cross Frame Scripting was not enabled or was not set properly.")
          print '    Value returned:', response.info().getheader('x-frame-options')
        else:
          print("X-Frame-Options\t\t\t\t\tCheck\t\t Cross Frame Scripting was not enabled or was not set properly.")
          print '    Value returned:', response.info().getheader('x-frame-options')

    
    
    print('\n\n=========================================')
    print('Checking for information disclosure...')
    print('=========================================')

    #Check for server
    if response.info().getheader('server'):
        print('Server\t\t\t\t\t\tCheck\t\t server was set.')
        print '    Value returned:', response.info().getheader('server')
    else:
        print('Server\t\t\t\t\t\tOK\t\t server was not set.')

    #Check for x-powered-by
    if response.info().getheader('x-powered-by'):
        print('X-Powered-By\t\t\t\t\tCheck\t\t x-powered-by was set.')
        print '    Value returned:', response.info().getheader('x-powered-by')
    else:
        print('X-Powered-By\t\t\t\t\tOK\t\t x-powered-by was not set.')
if __name__ == '__main__':
    main()


###lets  get the ciphers

#import additional modules
import subprocess
import os

#Lets format our input first
userurl = sys.argv[1]
url = userurl.replace("http://", "")

#Tell the user what we are doing
print('\n\n=========================================')
print 'Identifying Weak Ciphers used by ', url
print '      This may take some time...'
print('=========================================')


#To check for ciphers we're goping to use NMap - no need to reinvet the wheel
nmapout = subprocess.check_output(["/usr/bin/nmap", "-p443 ", url, "--script", "ssl-enum-ciphers"])
scanresults = open('scan.txt', 'w')
scanresults.write(nmapout)
scanresults.close()

filter = subprocess.check_output(["grep", "-v", "A$", "scan.txt" ])
scanresults = open('scan.txt', 'w')
scanresults.write(filter)
scanresults.close()

filter2 = subprocess.check_output(["grep", "TLS\|SSL", "scan.txt" ])
cleanout = filter2.replace("|   ","")
scanresults = open('scan.txt', 'w')
scanresults.write(filter2)
scanresults.close()
os.remove("scan.txt")
print cleanout

