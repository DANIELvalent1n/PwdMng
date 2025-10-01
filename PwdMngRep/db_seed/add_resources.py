from app import Resources

# 35 resurse de adăugat: (nume, tip, departament)
resources_to_add = [
    ("Laptop Dell XPS 13", "Hardware", "IT"),
    ("Laptop MacBook Pro", "Hardware", "IT"),
    ("Server Database", "Hardware", "IT"),
    ("VPN Access", "Software", "IT"),
    ("Git Repository", "Software", "IT"),
    ("HR Policies Document", "Document", "HR"),
    ("Employee Handbook", "Document", "HR"),
    ("Recruitment Portal", "Software", "HR"),
    ("Time Tracking App", "Software", "HR"),
    ("Payroll System", "Software", "HR"),
    ("Finance Reports Q1", "Document", "Finance"),
    ("Finance Reports Q2", "Document", "Finance"),
    ("Accounting Software", "Software", "Finance"),
    ("Budget Spreadsheet", "Document", "Finance"),
    ("Expense Tracker", "Software", "Finance"),
    ("Marketing Analytics Dashboard", "Software", "Marketing"),
    ("Brand Guidelines", "Document", "Marketing"),
    ("Campaign Calendar", "Document", "Marketing"),
    ("Social Media Accounts", "Software", "Marketing"),
    ("Ad Creatives", "Document", "Marketing"),
    ("Operations Manual", "Document", "Operations"),
    ("Inventory System", "Software", "Operations"),
    ("Warehouse Access", "Hardware", "Operations"),
    ("Logistics Dashboard", "Software", "Operations"),
    ("Maintenance Schedule", "Document", "Operations"),
    ("Sales CRM", "Software", "Sales"),
    ("Client Database", "Document", "Sales"),
    ("Product Catalog", "Document", "Sales"),
    ("Sales Reports", "Document", "Sales"),
    ("Lead Tracker", "Software", "Sales"),
    ("Customer Support Portal", "Software", "Support"),
    ("FAQ Documents", "Document", "Support"),
    ("Ticketing System", "Software", "Support"),
    ("Service Manuals", "Document", "Support"),
    ("Helpdesk Scripts", "Document", "Support"),
]

def add_resources(resources):
    res = Resources()
    for name, rtype, dept in resources:
        res.add_resource(name, rtype, dept)
        print(f"[+] Resource added: {name} ({rtype}) for {dept}")

if __name__ == "__main__":
    add_resources(resources_to_add)
