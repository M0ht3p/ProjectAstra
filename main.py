from asyncio import run, gather, TimeoutError
from argparse import ArgumentParser
from sys import exit
from dns.asyncresolver import Resolver
from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers

DEFAULT_SELECTORS = [
    "default", "google", "k1", "k2", "s1", "s2", "s2048", "selector1",
    "mail", "smtp", "dkim", "mandrill", "sendgrid", "mailchimp", "hubspot",
    "zendesk", "freshdesk", "zoho", "amazonses", "pm", "sig1"
]

HEADER = """
==================================================
                 Project ASTRA                   
    Authenticated Signature & TXT Record Analyzer 
==================================================
"""

async def check_dkim(domain: str, selector: str, resolver: Resolver) -> dict | None:
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        answers = await resolver.resolve(dkim_domain, 'TXT')
        records = []
        for rdata in answers:
            txt_content = "".join([part.decode('utf-8', errors='ignore') for part in rdata.strings])
            if "v=DKIM1" in txt_content or "p=" in txt_content:
                records.append(txt_content)
        
        if records:
            return {
                "selector": selector,
                "domain_key": dkim_domain,
                "records": records
            }
    except (NXDOMAIN, NoAnswer, NoNameservers, TimeoutError):
        pass
    except Exception:
        pass
    return None

async def run_lookup(domain: str, selectors: list[str]):
    print(HEADER)
    print(f"[*] Target Domain : {domain}")
    print(f"[*] Selectors    : {len(selectors)} queued for scan")
    print("-" * 50)

    resolver = Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    tasks = [check_dkim(domain, sel, resolver) for sel in selectors]
    results = await gather(*tasks)

    found = [r for r in results if r is not None]

    if not found:
        print("[-] No active DKIM records found for given selectors.")
        return

    print(f"[+] Found {len(found)} active DKIM record(s):\n")
    for item in found:
        print(f"[+] Selector : {item['selector']}")
        print(f"    Record   : {item['domain_key']}")
        for rec in item['records']:
            print(f"    Key TXT  : {rec}")
        print("-" * 50)

def main():
    parser = ArgumentParser(description="Project ASTRA - Authenticated Signature & TXT Record Analyzer")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-s", "--selectors", nargs="+", help="Custom selectors to test", default=DEFAULT_SELECTORS)
    
    args = parser.parse_args()
    
    clean_domain = args.domain.replace("https://", "").replace("http://", "").strip("/").strip()

    try:
        run(run_lookup(clean_domain, args.selectors))
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user.")
        exit(0)

if __name__ == "__main__":
    main()
