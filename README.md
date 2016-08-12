# HTTP Checks

This script peforms the following header checks
- HTTP Options
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
- x-frame-options*
- x-powered-by
- Server
- Ciphers**

# Important Notes
*Now, when it comes to the x-frame-options check, OWASP Tells us we can remediate this in two places
  - At the Hosted Level
  - In the Webpage - inside the HEAD Tag
We need to check both
see https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet for details

** To check for the ciphers we use nmap - this will need to be installed on your system
Using nmap means its really easy to code, but nmap applies a rating to each of the ciphers - the script shows everything that is not an 'A'

#Usage
HTTPSchecks.py http://www.domain.com

#Kudos
As you will see this is a fork from a project by Todd Benson (https://github.com/ToddBenson) so really alot of the Kudos goes to him
