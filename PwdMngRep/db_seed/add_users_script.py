from app import add_signup_request

DOMAIN = "safevaultcorp.com"

def email(user):
    return f"{user}@{DOMAIN}"

# 15 conturi Employee
employee_accounts = [
    (email("john.doe"), "Passw0rd!1", "John Doe", "IT", "employee"),
    (email("jane.smith"), "Secur3Pwd!2", "Jane Smith", "HR", "employee"),
    (email("alex.brown"), "MyStr0ngPwd!3", "Alex Brown", "Finance", "employee"),
    (email("linda.wu"), "P@ssw0rdWu4", "Linda Wu", "Marketing", "employee"),
    (email("michael.lee"), "Saf3tyLee!5", "Michael Lee", "Operations", "employee"),
    (email("sarah.jones"), "Jones!Pwd6", "Sarah Jones", "Sales", "employee"),
    (email("dan.popescu"), "DanP@ss!7", "Dan Popescu", "IT", "employee"),
    (email("maria.ionescu"), "MariaPwd!8", "Maria Ionescu", "HR", "employee"),
    (email("george.stan"), "StanStrong!9", "George Stan", "Finance", "employee"),
    (email("ioana.vasilescu"), "IoanaPwd@10", "Ioana Vasilescu", "Operations", "employee"),
    (email("paul.radu"), "Radu!Pwd11", "Paul Radu", "IT", "employee"),
    (email("andreea.ilie"), "IliePass@12", "Andreea Ilie", "Marketing", "employee"),
    (email("cosmin.nistor"), "NistorPwd!13", "Cosmin Nistor", "Sales", "employee"),
    (email("elena.tudor"), "TudorPwd@14", "Elena Tudor", "HR", "employee"),
    (email("robert.enache"), "EnachePwd!15", "Robert Enache", "Finance", "employee"),
]

# 25 conturi HR
hr_accounts = [
    (email("cristina.popa"), "HR1Pass!16", "Cristina Popa", "HR", "hr"),
    (email("adela.matei"), "HR12Pass!27", "Adela Matei", "HR", "hr"),
    (email("florin.toma"), "HR13Pass!28", "Florin Toma", "HR", "hr"),
    (email("ioan.mihai"), "HR14Pass!29", "Ioan Mihai", "HR", "hr"),
    (email("valentina.pavel"), "HR15Pass!30", "Valentina Pavel", "HR", "hr"),
    (email("costel.rusu"), "HR16Pass!31", "Costel Rusu", "HR", "hr"),
    (email("lavinia.ene"), "HR17Pass!32", "Lavinia Ene", "HR", "hr"),
    (email("andrei.tanase"), "HR18Pass!33", "Andrei Tănase", "HR", "hr"),
    (email("monica.oprea"), "HR19Pass!34", "Monica Oprea", "HR", "hr"),
    (email("nicolae.gheorghiu"), "HR20Pass!35", "Nicolae Gheorghiu", "HR", "hr"),
    (email("madalina.petrescu"), "HR21Pass!36", "Mădălina Petrescu", "HR", "hr"),
    (email("sergiu.vasile"), "HR22Pass!37", "Sergiu Vasile", "HR", "hr"),
]

# 10 conturi Manager
manager_accounts = [
    (email("ana.georgescu"), "Mng1Pass!41", "Ana Georgescu", "Management", "manager"),
    (email("lucian.pavel"), "Mng2Pass!42", "Lucian Pavel", "Management", "manager"),
    (email("irina.costache"), "Mng3Pass!43", "Irina Costache", "Management", "manager"),
    (email("cristian.lupu"), "Mng4Pass!44", "Cristian Lupu", "Management", "manager"),
    (email("mihaela.neagu"), "Mng5Pass!45", "Mihaela Neagu", "Management", "manager"),
    (email("alex.calin"), "Mng6Pass!46", "Alex Călin", "Management", "manager"),
    (email("roxana.iliescu"), "Mng7Pass!47", "Roxana Iliescu", "Management", "manager"),
    (email("ovidiu.preda"), "Mng8Pass!48", "Ovidiu Preda", "Management", "manager"),
    (email("carmen.diaconu"), "Mng9Pass!49", "Carmen Diaconu", "Management", "manager"),
    (email("stefania.dima"), "Mng10Pass!50", "Ștefania Dima", "Management", "manager"),
]

# Rulează inserțiile
if __name__ == "__main__":
    all_accounts = employee_accounts + hr_accounts + manager_accounts
    for u, p, n, d, r in all_accounts:
        ok = add_signup_request(u, p, n, d, r)
        if ok:
            print(f"[+] Signup request added for {u} ({r})")
        else:
            print(f"[!] Could not add signup request for {u} (maybe username already exists)")
