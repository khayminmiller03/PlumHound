"""
This is a file is a testing harness of the neo4j querys and to convert the
old default.tasks file to 'default.yaml', for example.
It also checks to make sure there are no out of date queries to make things easily
maintainable.



USAGE:
C:../PlumHound
uv run .\neo4jScript.py
or
python .\neo4jScript.py


YAML runner:

python PlumHound.py -s "bolt://localhost:7687" -u neo4j -p "bloodhoundcommunityedition" -y .\tasks\testing.yml
"""

import json
import re
from pathlib import Path

import yaml
from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = "bloodhoundcommunityedition"
TASKFILE = r".\tasks\*.tasks"

driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
DIRECTIVES = {"REPORT-INDEX", "ZIP-TASKS"}

cat = {
    # Domain
    "Domains": "Domain",
    "Domain Trusts": "Domain",
    "Domain Controllers": "Domain",
    "Domain Controllers - Read Only": "Domain",

    # Inventory
    "Domain User Accounts": "Inventory",
    "Domain Computer Accounts": "Inventory",
    "Domain Groups": "Inventory",
    "OUs By Computer Member Count": "Inventory",
    "OUs By User Member Count": "Inventory",
    "OUs By Group Member Count": "Inventory",

    # Privilege
    "Enterprise Admins (Direct)": "Privilege",
    "Schema Admins (Direct)": "Privilege",
    "Domain Admins (Direct)": "Privilege",
    "Admin Groups": "Privilege",
    "Admin Groups Direct Population": "Privilege",
    "Cert Publishers (Direct)": "Privilege",
    "HighValue Group Members (Direct) (Limited to 1000)": "Privilege",
    "Protected Users Group (Direct)": "Privilege",
    "Admins Without Sensitive Protection Flag": "Privilege",
    "Pre-Windows 2000 Compatibility Access Direct Members": "Privilege",
    "Domain Controller Owners": "Privilege",
    "Domain Controller Owned by Users": "Privilege",
    "Users (Non-Admin) With AddMember Group Permissions": "Privilege",
    "PasswordResetter Groups Count": "Privilege",

    # DCSync
    "DCSync Direct Relationships": "DCSync",
    "DCSync Privileged Non-DCs": "DCSync",
    "DCSync Privileged Non-DAs": "DCSync",

    # Kerberos
    "Kerberoastable Users": "Kerberos",
    "User No Kerb Needed (AS-REP Roastable Users)": "Kerberos",
    "Unconstrained Delegation Users with SPN": "Kerberos",
    "Unconstrained Delegation Computers with SPN": "Kerberos",
    "Unconstrained Delegation Computers with SPN Non-DC": "Kerberos",
    "Constrained Delegation - All": "Kerberos",
    "Constrained Delegation - Users": "Kerberos",
    "Constrained Delegation - Users NonDA": "Kerberos",
    "Constrained Delegation - Computers NonDC": "Kerberos",
    "Computers with MSSQL SPN": "Kerberos",

    # GPO
    "GPOs": "GPO",
    "GPO OU Links": "GPO",
    "GPO Owners Summary Count": "GPO",
    "GPO Owners Detail": "GPO",
    "GPO Owners - Non-(Direct)DAs": "GPO",
    "GPOS - Non-(Direct)DA Users With Interesting GPO Permissions": "GPO",
    "GPO Creator Owners (Direct)": "GPO",

    # Exposure
    "Direct Relationships - Everyone": "Exposure",
    "Direct Relationships - Authenticated Users": "Exposure",
    "Direct Relationships - Pre-Windows 2000 Compatibility Access": "Exposure",
    "Direct Relationships - Domain Users": "Exposure",
    "Direct Relationships - Domain Computers": "Exposure",
    "Direct Relationships - Users": "Exposure",
    "Direct Relationships - Guests": "Exposure",

    # Access
    "DA Sessions": "Access",
    "EA Sessions": "Access",
    "User Sessions Count": "Access",
    "Users Sessions": "Access",
    "Users Sessions Count": "Access",
    "RDPable Servers": "Access",
    "RDPable Groups": "Access",
    "RDPable Groups Count": "Access",

    # Local Admin
    "Computers Vulnerable to Local Admin Enumeration": "Local Admin",
    "Local Admins - Groups": "Local Admin",
    "Local Admins - Groups Count": "Local Admin",
    "Local Admins - Users": "Local Admin",
    "Local Admins - Users Count": "Local Admin",
    "Local Admins - Computers": "Local Admin",
    "Local Admins - Computers Count": "Local Admin",

    # Systems
    "Computers with Descriptions": "Systems",
    "Operating Systems Unsupported": "Systems",
    "Operating Systems Unsupported Count": "Systems",
    "Operating Systems Count": "Systems",
    "LAPS Deployment Count": "Systems",
    "LAPS Deployment OS Count": "Systems",
    "LAPS Not Enabled": "Systems",
    "GMSA Read Permissions - Direct": "Systems",

    # Hygiene
    "Users With < 1 Day Old Passwords": "Hygiene",
    "Users With < 7 Day Old Passwords": "Hygiene",
    "Users With < 30 Day Old Passwords": "Hygiene",
    "Users With > 6 Month Old Passwords": "Hygiene",
    "Users With > 1 Year Old Passwords": "Hygiene",
    "Users With > 5 Year Old Passwords": "Hygiene",
    "Users With > 10 Year Old Passwords": "Hygiene",
    "Users With > 15 Year Old Passwords": "Hygiene",
    "Users With > 20 Year Old Passwords": "Hygiene",
    "Users Password Never Expires Exception": "Hygiene",
    "Users Password Not Required": "Hygiene",
    "Users Password Not Required and Never Set": "Hygiene",
    "Users With Userpassword Attribute": "Hygiene",
    "Users Not Active 6 Months": "Hygiene",
    "Users Not Active 12 Months": "Hygiene",
    "Users Not Active 60 Months": "Hygiene",
    "Users Not Active 120 Months": "Hygiene",
    "Users Never Active": "Hygiene",

    # Hunt
    "Hunt - Users with Pass or PW in Description": "Hunt",
    "Hunt - Users with Change in Description": "Hunt",
    "Hunt - Users with VPN Group": "Hunt",
    "Hunt - Computers with Pass or PW in Description": "Hunt",

    # Owned
    "Owned Groups": "Owned",
    "Owned Users": "Owned",
    "Owned Computers": "Owned",
    "Owned Users Group Membership": "Owned",
    "Owned Computers Group Membership": "Owned",
    "Owned Users Group Membership (Direct Distinct)": "Owned",
    "Owned Computers Group Membership (Direct Distinct)": "Owned",
    "Owned Users Interesting Relationships": "Owned",
    "Owned Computers Interesting Relationships": "Owned",
    "Owned Objects": "Owned",
    "Owned Objects Admin To": "Owned",
    "Owned Objects Member Of (Direct)": "Owned",
    "Owned Objects Read GMSA Password - Recursive": "Owned",

    # Certificates
    "Certificate Templates": "Certificates",
    "Certificate Authorities": "Certificates",
    "Certificate Enrollment Rights": "Certificates",
    "Certificate Template ESC1 Vuln": "Certificates",
    "Certificate Template ESC2 Vuln": "Certificates",
    "Certificate Template ESC3 Vuln": "Certificates",
    "Certificate Template ESC6 Vuln": "Certificates",
    "Certificate Template ESC8 Vuln": "Certificates",

    # System (directives)
    """
    the two System tasks are directives not queries,
    the highvalue queries are inert until data has system_tags
    """
    "Report Index": "System",
    "Zip Tasks": "System",
}

try:
    driver.verify_connectivity()
    print("Connected to Neo4j")
except Exception as e:
    print("Connection Failed: ", e)
    exit()

TASKFILE = r".\tasks\*.tasks"

def to_yaml(title, category, kind, form, out, cypher):
    cypher_block = "\n".join(f"    {line}" for line in cypher.splitlines())
    return (
        f"- title: {json.dumps(title)}\n"
        f"  category: {category}\n"
        f"  type: {kind}\n"
        f"  format: {form}\n"
        f"  output: {out}\n"
        f"  cypher: >\n"
        f"{cypher_block}\n"
    )


tasks = []
for in_path in Path("tasks").glob("*.tasks"):
    out_path = in_path.with_suffix(".yml")
    with open(in_path, encoding="utf-8") as f, \
         open(out_path, "w", encoding="utf-8") as g:
        for line in f:
            line = line.strip()
            if not line.startswith("["):
                continue
            line = line.replace("\\'", "'")
            try:
                title, form, out, cypher = json.loads(line)[:4]
            except (json.JSONDecodeError, ValueError) as e:
                print(f"Skipped line in {in_path.name}: {e}")
                continue

            clean_title = re.sub(r"\s+", " ", title).strip()
            category = cat.get(clean_title, "Uncategorized")
            kind = "directive" if cypher.strip().upper() in DIRECTIVES else "cypher"

            entry = to_yaml(title, category, kind, form, out, cypher)
            #print(entry)
            g.write(entry + "\n")
            tasks.append((title, cypher))

print(f"Loaded {len(tasks)} tasks")




tasks = []
for in_path in Path("tasks").glob("*.yml"):
    with open(in_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
        if not data:
            print(f"Skipping empty file: {in_path}")
            continue
        for t in data:
            title = t.get("title")
            cypher = t.get("cypher")
            ttype = t.get("type")
            tasks.append((title, cypher, ttype))

works = 0
empty = 0
errors = 0
skipped = 0

with driver.session() as session:
    for title, cypher, ttype in tasks:
        if ttype == "directive":
            skipped += 1
            continue
        try:
            records = list(session.run(cypher))
            if len(records) > 0:
                works += 1
            else:
                empty += 1
        except Exception as e:
            errors += 1
            print(f"[ERROR] {title}: {e}")

print(f"\nSummary: {works} works, {empty} empty, {errors} errors, {skipped} directives skipped")

