# NetworkMaster DNS Checker v1.2.0

Production update for the new NetworkMaster website structure, UI, routing and cleanup.

## Highlights

- Moved DNS Checker to the new tool route:
  - /tools/dns-checker/
  - /tools/dns-checker/fa/
- Added the new NetworkMaster homepage structure.
- Added the homepage source snapshot under networkmaster-main/.
- Unified the default navbar style between homepage and DNS Checker.
- Added Persian navbar tuning for the DNS Checker Persian page.
- Improved language switching between English and Persian DNS Checker pages.
- Updated footer structure and links to match the new /tools/... route layout.
- Cleaned unused public backup files and old logo artifacts.
- Kept only production-required public assets.
- Added recovery documentation and production restore assets.
- Improved custom 404 and upstream error page handling.
- Preserved DNS Checker backend, public DNS provider checks, and agent-based checks.

## Routes

- Homepage:
  - https://networkmaster.org/
- DNS Checker:
  - https://networkmaster.org/tools/dns-checker/
- Persian DNS Checker:
  - https://networkmaster.org/tools/dns-checker/fa/

## Notes

- The old dns.networkmaster.org subdomain is no longer the primary route.
- The project is now structured around networkmaster.org/tools/... for future tools.
- Future tools can be added under:
  - /tools/whois/
  - /tools/ssl-checker/
  - /tools/ip-lookup/
  - /tools/port-checker/
  - /tools/traceroute/
  - /tools/ping/
