Put a CISA KEV catalogue here as `kev.json` before starting the development stack. Without it, every job reports the known-exploited check as incomplete.

```
curl --proto '=https' -fsSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o deploy/dev-kev/kev.json
```
