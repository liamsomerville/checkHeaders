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
- x-powered-by
- Server
- Ciphers

Now, when it comes to the x-frame-options check, OWASP Tells us we can remediate this in two places
  - At the Hosted Level
  - In the Webpage - inside the <HEAD> Tag
We need to check both
see https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet for details

#Usage
HTTPScheck.py http://www.domain.com

#Kudos
As you will see this is a fork from a project by Todd Benson (https://github.com/ToddBenson) so really alot of the Kudos goes to him
