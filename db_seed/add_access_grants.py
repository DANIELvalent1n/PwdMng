from app import Employees, AccessGrant

def copy_existing_grants():
    access = AccessGrant()
    emp = Employees()

    # ia toți userii activi din Employees
    conn = emp.get_connection()
    users = conn.execute("SELECT id, username, role FROM Employees WHERE status='active'").fetchall()
    conn.close()

    for u in users:
        username = u["username"]
        role = u["role"]

        # ia permisiunile curente (overrides) dacă există în AccessGrant
        existing = access.show_access_grants()  # listă de dicturi
        over = None
        for grant in existing:
            if grant["username"] == username:
                over = grant.get("overrides", None)
                break

        # dacă nu există overrides, setăm un default similar cu rolul
        if not over:
            over = "full_access" if role in ["admin", "manager"] else "limited"

        # adresa email - presupunem că e username@safevaultcorp.com
        email_addr = f"{username}@safevaultcorp.com"

        access.grant_access(username=username, role=role, overrides=over)
        print(f"[+] Access granted: {username}")

if __name__ == "__main__":
    copy_existing_grants()
