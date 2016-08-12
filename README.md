# checkHeaders
Check HTTP Response Headers for Security Headers

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
