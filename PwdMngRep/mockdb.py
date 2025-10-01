import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
import secrets
import string
import hmac
import base64
import hashlib

#Create class database
class DataBase:

    def __init__(self):
        self.path = Path(__file__).resolve().parent / "password_and_access_manager.db"

    def get_connection(self):
        """Returnează o conexiune la baza de date SQLite."""
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row   # pentru rezultate ca dict
        return conn
    
    def init_db(self):
        """Creează tabelele dacă nu există."""
        conn = self.get_connection()
        c = conn.cursor()

        #Tabel pentru angajati
        c.execute("""
        CREATE TABLE IF NOT EXISTS Employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        name TEXT,
        dept TEXT,
        role TEXT,
        address TEXT,
        salary INT,
        status TEXT
    )
    """)
        
        c.execute("""
        CREATE TABLE IF NOT EXISTS Roles (
        name TEXT UNIQUE NOT NULL,
        permissions TEXT
    )
    """)
        
        #Resource: id, name, type, owner_dept
        c.execute("""
        CREATE TABLE IF NOT EXISTS Resources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        type TEXT,
        owner_dept TEXT
    )
    """)
        
        #Credential: resource_id, username, secret(enc), rotation_date, tags[]
        c.execute("""
        CREATE TABLE IF NOT EXISTS Credentials (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME NOT NULL,
        rotation_date DATETIME NOT NULL
    )
    """)

        #AuditEvent: ts, actor, action, entity, details
        c.execute("""
        CREATE TABLE IF NOT EXISTS AuditEvent (
        timestamp TIMESTAMP PRIMARY KEY,
        actor TEXT NOT NULL,
        action TEXT,
        details TEXT)
    """)
        
        c.execute("""
        CREATE TABLE IF NOT EXISTS AccessGrant (
        employee_id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_username TEXT,
        role TEXT,
        overrides TEXT)
    """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS SignupRequests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        dept TEXT,
        role TEXT,
        status TEXT DEFAULT 'pending')
    """)

        conn.commit()
        conn.close()

    def add_backup(self):
        backup_dbname = self.path.parent / "password_and_access_manager_backup.db"
        with sqlite3.connect(self.path) as source, sqlite3.connect(backup_dbname) as dest:
            source.backup(dest)

class Employees(DataBase): 
    def __init__(self, actor="SYSTEM"):
        super().__init__()
        self.actor = actor
        #self.init_db()
        self.username = ""
        self.name = "" 
        self.dept = "" 
        self.role = "" 
        self.salary = 0
        self.status = ""

    def add_employee(self, username, name=None, dept=None, role=None, salary=0, status=None):
        conn = self.get_connection()
        try:
            conn.execute("""
                INSERT INTO Employees (username, name, dept, role, salary, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, name, dept, role, salary, status))
            conn.commit()
            print(f"Employee '{username}' added.")

            AuditEvent().log_event(self.actor, "EMPLOYEE_ADDED",
                                   f"Employee {username} added in dept {dept} with role {role}.")
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def del_employee(self, username):
        conn = self.get_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM Employees WHERE username = ?", (username,))
            row = c.fetchone()
            if row is None:
                print(f"Employee '{username}' not found.")
                return False

            conn.execute("DELETE FROM Employees WHERE username = ?", (username,))
            conn.commit()
            print(f"Employee '{username}' deleted.")

            AuditEvent().log_event(self.actor, "EMPLOYEE_DELETED",
                                   f"Employee {username} removed.")
            return True
        finally:
            conn.close()

    def update_employee(self, username, name=None, dept=None, role=None, salary=0, status=None):
        conn = self.get_connection()
        c = conn.cursor()
        try:
            updates, params = [], []
            if name is not None:
                updates.append("name = ?")
                params.append(name)
            if dept is not None:
                updates.append("dept = ?")
                params.append(dept)
            if role is not None:
                updates.append("role = ?")
                params.append(role)
            if salary is not None:
                updates.append("salary = ?")
                params.append(salary)
            if status is not None:
                updates.append("status = ?")
                params.append(status)

            if not updates:
                print("No fields to update.")
                return False

            params.append(username)
            sql = f"UPDATE Employees SET {', '.join(updates)} WHERE username = ?"
            c.execute(sql, params)
            conn.commit()

            if c.rowcount == 0:
                print(f"No employee found with username '{username}'.")
                return False

            print(f"Employee '{username}' updated successfully.")

            AuditEvent().log_event(self.actor, "EMPLOYEE_UPDATED",
                                   f"Employee {username} updated with {updates}.")
            return True
        finally:
            conn.close()

    def show_employees(self):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM Employees")
        # This SQL statement selects all data from the CUSTOMER table.
        result = c.fetchall()
        # Printing all records or rows from the table.
        # It returns a result set. 
        conn.close()
        return result

    def soft_delete_employee(self, username):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("UPDATE Employees SET status='deleted', name=name WHERE username=?", (username,))
        AuditEvent().log_event(self.actor, "EMPLOYEE_SOFT_DELETED",
                                   f"Employee {username} was soft deleted.")
        conn.commit()
        conn.close()

    def undo_delete_employee(self, username):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("UPDATE Employees SET status='active' WHERE username=? AND status='deleted'", (username,))
        AuditEvent().log_event(self.actor, "EMPLOYEE_ADDED_BACK",
                                   f"Employee {username} was added back.")
        conn.commit()
        conn.close()


class Roles(DataBase):
    def __init__(self, actor="SYSTEM"):
        super().__init__()
        self.actor = actor

    def add_role(self, name=None, permissions=None):
        conn = self.get_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM Roles WHERE name = ?", (name,))
            row = c.fetchone()
            if row:
                print(f"Role '{name}' already exists.")
                return False
            conn.execute("""
                INSERT INTO Roles (name, permissions)
                VALUES (?, ?)
            """, (name, permissions))
            conn.commit()
            print(f"Role '{name}' added.")

            AuditEvent().log_event(self.actor, "ROLE_ADDED",
                                   f"Role {name} created with permissions {permissions}.")
        finally:
            conn.close()

    def update_role(self, name=None, permissions=None):
        conn = self.get_connection()
        c = conn.cursor()
        try:
            updates, params = [], []
            if name is not None:
                updates.append("name = ?")
                params.append(name)
            if permissions is not None:
                updates.append("permissions = ?")
                params.append(permissions)

            if not updates:
                print("No fields to update.")
                return False

            sql = f"UPDATE Roles SET {', '.join(updates)} WHERE name = ?"
            params.append(name)
            c.execute(sql, params)
            conn.commit()

            if c.rowcount == 0:
                print(f"No role found with name '{name}'.")
                return False

            print(f"Role '{name}' updated successfully.")

            AuditEvent().log_event(self.actor, "ROLE_UPDATED",
                                   f"Role {name} updated with {updates}.")
            return True
        finally:
            conn.close()

    def show_roles(self):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM Roles")
        # This SQL statement selects all data from the CUSTOMER table.
        result = c.fetchall()
        # Printing all records or rows from the table.
        # It returns a result set. 
        conn.close()
        return [row[0] for row in result]


class Resources(DataBase):
    def __init__(self, actor="SYSTEM"):
        super().__init__()
        self.actor = actor

    def add_resource(self, name=None, type=None, owner_dept=None):
        conn = self.get_connection()
        try:
            conn.execute("""
                INSERT INTO Resources (name, type, owner_dept)
                VALUES (?, ?, ?)
            """, (name, type, owner_dept))
            conn.commit()
            AuditEvent().log_event(self.actor, "RESOURCE_ADDED",
                                   f"Resource {name} ({type}) owned by {owner_dept}.")
        finally:
            conn.close()

    def del_resource(self, id, owner_dept):
        conn = self.get_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM Resources WHERE id = ? AND owner_dept = ?", (id, owner_dept))
            row = c.fetchone()
            if row is None:
                print(f"Resource '{id}' with dept '{owner_dept}' not found.")
                return False

            conn.execute("DELETE FROM Resources WHERE id = ?", (id,))
            conn.commit()
            AuditEvent().log_event(self.actor, "RESOURCE_DELETED",
                                   f"Resource {id} from dept {owner_dept} removed.")
            return True
        finally:
            conn.close()
    
    def update_resource(self, id, name, type, owner_dept):
        conn = self.get_connection()
        c = conn.cursor()
        try:
            updates, params = [], []
            if id is not None:
                updates.append("id = ?")
                params.append(id)
            if name is not None:
                updates.append("name = ?")
                params.append(name)
            if type is not None:
                updates.append("type = ?")
                params.append(type)
            if owner_dept is not None:
                updates.append("owner_dept = ?")
                params.append(owner_dept)

            if not updates:
                print("No fields to update.")
                return False

            sql = f"UPDATE Resources SET {', '.join(updates)} WHERE id = ?"
            params.append(id)
            c.execute(sql, params)
            conn.commit()

            if c.rowcount == 0:
                return False

            print(f"Resource '{name}' updated successfully.")

            AuditEvent().log_event(self.actor, "RESOURCE_UPDATED",
                                   f"Resource {name} updated with {updates}.")
            return True
        finally:
            conn.close()

    def show_resources(self):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM Resources")
        # This SQL statement selects all data from the CUSTOMER table.
        result = c.fetchall()
        # Printing all records or rows from the table.
        # It returns a result set. 
        conn.close()
        return [row[0] for row in result]


# ===================== Simple Crypto =====================
class SimpleCryptoProvider:
    """
    Simple XOR + Base64 encryption/decryption.
    Accepts strings, returns strings.
    """
    def __init__(self, key: bytes = b"mock-secret-key"):
        import hashlib
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plaintext: str) -> str:
        data = plaintext.encode('utf-8')  # encode string to bytes
        xored = bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(data)])
        return base64.urlsafe_b64encode(xored).decode('ascii')

    def decrypt(self, ciphertext: str) -> str:
        raw = base64.urlsafe_b64decode(ciphertext.encode('ascii'))
        xored = bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(raw)])
        return xored.decode('utf-8', errors='ignore')  # safely decode


# ===================== Credentials =====================
class Credentials(DataBase):
    """
    Credentials manager with pluggable crypto + password policies.
    """

    # ---------- Strategy Interfaces ----------
    class CryptoProvider:
        def encrypt(self, plaintext: bytes) -> str: raise NotImplementedError
        def decrypt(self, ciphertext: str) -> bytes: raise NotImplementedError

    class PasswordPolicy:
        def generate(self) -> str: raise NotImplementedError

    # ---------- Password policies ----------
    class SimplePolicy(PasswordPolicy):
        def __init__(self, length=12, specials=False):
            self.length = length
            self.specials = specials

        def generate(self) -> str:
            alphabet = string.ascii_letters + string.digits
            if self.specials:
                alphabet += "!@#$%^&*"
            return "".join(secrets.choice(alphabet) for _ in range(self.length))

    class StrongPolicy(SimplePolicy):
        def __init__(self, length=20):
            super().__init__(length, specials=True)

    # ---------- Main ----------
    def __init__(self, crypto_provider=None, password_policy=None, actor="SYSTEM"):
        super().__init__()
        self.crypto = crypto_provider or SimpleCryptoProvider()
        self.policy = password_policy or self.StrongPolicy()
        self.init_db()
        self.actor = actor

    # ---------- Add credential ----------
    def add_credential(self, username, password=None, rotation_date=None):
        password = password or self.policy.generate()
        cipher = self.crypto.encrypt(password)
        created = datetime.now(timezone.utc)
        rotation = rotation_date or (created + timedelta(days=180))

        conn = self.get_connection()
        try:
            conn.execute("""
                INSERT INTO Credentials (username, password, created_at, rotation_date)
                VALUES (?, ?, ?, ?)
            """, (username, cipher, created.isoformat(), rotation.isoformat()))
            conn.commit()
            print(f"Credential for '{username}' added.")

            AuditEvent().log_event(self.actor, "CREDENTIAL_CREATED",
                                   f"Credential for {username} created.")
        except sqlite3.IntegrityError:
            print(f"Credential for '{username}' already exists.")
        finally:
            conn.close()

    # ---------- Get credential ----------
    def get_credential(self, username):
        conn = self.get_connection()
        row = conn.execute("SELECT * FROM Credentials WHERE username=?", (username,)).fetchone()
        conn.close()
        if not row:
            return None
        pw = self.crypto.decrypt(row["password"])
        AuditEvent().log_event(self.actor, "CREDENTIAL_VIEWED",
                               f"Credential for {username} accessed.")
        return pw

    # ---------- List credentials ----------
    def list_credentials(self):
        conn = self.get_connection()
        rows = conn.execute("SELECT id, username, created_at, rotation_date FROM Credentials").fetchall()
        conn.close()
        return rows

    # ---------- Rotate credential ----------
    def rotate_credential(self, username, policy=None):
        new_pw = (policy or self.policy).generate()
        cipher = self.crypto.encrypt(new_pw)
        rotation = (datetime.now(timezone.utc) + timedelta(days=180)).isoformat()

        conn = self.get_connection()
        c = conn.cursor()
        c.execute(
            "UPDATE Credentials SET password=?, rotation_date=? WHERE username=?",
            (cipher, rotation, username)
        )
        conn.commit()
        conn.close()

        if c.rowcount:
            AuditEvent().log_event(self.actor, "CREDENTIAL_ROTATED",
                                   f"Credential for {username} rotated")
            return new_pw
        return None

    # ---------- Verify password ----------
    def verify_password(self, username, candidate):
        cred = self.get_credential(username)
        ok = cred and hmac.compare_digest(cred, candidate)
        if not ok:
            AuditEvent().log_event(self.actor, "CREDENTIAL_VERIFY_FAILED",
                                   f"Failed password check for {username}")
        return ok

    def update_password(self, username, new_password):
        cipher = self.crypto.encrypt(new_password)
        rotation = (datetime.now(timezone.utc) + timedelta(days=180)).isoformat()

        conn = self.get_connection()
        c = conn.cursor()
        c.execute(
            "UPDATE Credentials SET password=?, rotation_date=? WHERE username=?",
            (cipher, rotation, username)
        )
        conn.commit()
        conn.close()

        if c.rowcount:
            AuditEvent().log_event(self.actor, "CREDENTIAL_PASSWORD_UPDATED",
                                   f"Password for {username} updated")
            return True
        return False

    # ---------- Check expiring credentials ----------
    def check_expiring_credentials(self, days=14):
        now = datetime.now(timezone.utc)
        cutoff = now + timedelta(days=days)

        conn = self.get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT id, username, created_at, rotation_date  FROM Credentials 
            WHERE rotation_date <= ?
            ORDER BY rotation_date ASC
        """, (cutoff.isoformat(),))
        rows = c.fetchall()
        conn.close()

        return [dict(r) for r in rows]
    
    def check_time_remaining(self, username):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT rotation_date FROM Credentials WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        rotation_date = datetime.fromisoformat(row["rotation_date"])
        now = datetime.now(timezone.utc)
        delta = rotation_date - now
        return delta.days if delta.days >= 0 else 0
    
    def view_credential(self, username, state_user):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM Credentials WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        pw = self.crypto.decrypt(row["password"])
        AuditEvent().log_event(self.actor, "CREDENTIAL_VIEWED",
                               f"Credential for {username} accessed by {state_user}.")
        return pw

class AccessGrant(DataBase):
    
    def __init__(self, actor="SYSTEM"):
        super().__init__()
        self.username = ""
        self.role = ""
        self.overrides = ""
        self.actor = actor

    def grant_access(self, username, role, overrides=None):
        """
        Assign a role (and optional overrides) to an employee.
        """
        conn = self.get_connection()
        c = conn.cursor()
        try:
            # Find employee ID
            c.execute("SELECT id FROM Employees WHERE username=?", (username,))
            row = c.fetchone()
            if not row:
                print(f"Employee '{username}' not found.")
                return False
            emp_id = row["id"]

            # Check if grant already exists
            c.execute("SELECT * FROM AccessGrant WHERE employee_username=?", (username,))
            exists = c.fetchone()

            if exists:
                # Update if already exists
                c.execute(
                    "UPDATE AccessGrant SET role=?, overrides=? WHERE employee_username=?",
                    (role, overrides, username),
                )
                print(f"Access updated for '{username}' with role '{role}'.")
            else:
                # Insert new
                c.execute(
                    "INSERT INTO AccessGrant (employee_id, employee_username, role, overrides) VALUES (?, ?, ?, ?)",
                    (emp_id, username, role, overrides),
                )
                print(f"Access granted to '{username}' with role '{role}'.")
            AuditEvent().log_event(self.actor, "ACCESS GRANTED", f"Access granted or updated for {username} with role {role}: {overrides}")
            conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Error granting access: {e}")
            return False
        finally:
            conn.close()

    def check_access(self, username, permission):
        """
        Check if a user has a specific permission.
        """
        conn = self.get_connection()
        c = conn.cursor()
        try:
            # Get employee role
            c.execute("""
                SELECT ag.role, ag.overrides, r.permissions
                FROM Employees e
                JOIN AccessGrant ag ON e.id = ag.employee_id
                JOIN Roles r ON ag.role = r.name
                WHERE e.username=?
            """, (username,))
            row = c.fetchone()
            
            if not row:
                print(f"No access grant found for '{username}'.")
                return False

            role_perms = set((row["permissions"] or "").split(","))
            override_perms = set((row["overrides"] or "").split(",")) if row["overrides"] else set()
            effective_perms = role_perms.union(override_perms)

            return permission in effective_perms
        except sqlite3.Error as e:
            print(f"Error checking access: {e}")
            return False
        finally:
            conn.close()

    def revoke_access(self, username):
        """
        Remove access grant for an employee.
        """
        conn = self.get_connection()
        c = conn.cursor()
        try:
            c.execute("""
                DELETE FROM AccessGrant 
                WHERE employee_id = (SELECT id FROM Employees WHERE username=?)
            """, (username,))
            conn.commit()
            if c.rowcount == 0:
                print(f"No access grant found for '{username}'.")
                return False
            print(f"Access revoked for '{username}'.")
            AuditEvent().log_event(self.actor, "ACCESS REVOKED", f"Access revoked for user {username}.")
            return True
        except sqlite3.Error as e:
            print(f"Error revoking access: {e}")
            return False
        finally:
            conn.close()

    def show_access_grants(self):
        """
        List all access grants.
        """
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT e.username, ag.role, ag.overrides
            FROM AccessGrant ag
            JOIN Employees e ON ag.employee_id = e.id
        """)
        results = c.fetchall()
        conn.close()
        return results

class AuditEvent(DataBase):
    def __init__(self):
        super().__init__()
        self.init_db()

    def log_event(self, actor: str, action: str, details: str = None):
        """Insert a new audit event with UTC timestamp."""
        conn = self.get_connection()
        c = conn.cursor()
        try:
            ts = datetime.now(timezone.utc).isoformat()
            c.execute("""
                INSERT INTO AuditEvent (timestamp, actor, action, details)
                VALUES (?, ?, ?, ?)
            """, (ts, actor, action, details))
            conn.commit()
            print(f"[AUDIT] {actor} -> {action} @ {ts} ({details})")
            return True
        except sqlite3.Error as e:
            print(f"Error logging event: {e}")
            return False
        finally:
            conn.close()

    def list_events(self, limit=50):
        conn = self.get_connection()
        rows = conn.execute(
            "SELECT * FROM AuditEvent ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

if __name__ == "__main__":

    #db = DataBase()
    #db.init_db()
    # emp1 = Employees()
    # #emp1.add_employee(username="vlupas3")
    # print(emp1)
    # #emp1.del_employee(username="vlupas1")
    # #emp1.update_employee(username="vlupas", salary=10000)
    # emp1.show_employees()

    # creds = Credentials()

    # creds.add_credential("alice")
    # creds.add_credential("bob")

    # print("All credentials:", creds.list_credentials())
    # print("Get Alice:", creds.get_credential("alice"))

    # newpw = creds.rotate_credential("alice")
    # print("Alice rotated password:", newpw)
    # print("Verify new password:", creds.verify_password("alice", newpw))

    # print("Expiring in 14 days:", creds.check_expiring_credentials(14))

    # emp = Employees()

    # # Add an employee (will auto-log EMPLOYEE_ADDED)
    # emp.add_employee(username="alice", name="Alice Smith", dept="IT", role="Engineer", salary=70000, status="active")

    # # Update employee (auto-log EMPLOYEE_UPDATED)
    # emp.update_employee(username="alice", role="Senior Engineer", salary=85000)

    # # Delete employee (auto-log EMPLOYEE_DELETED)
    # emp.del_employee("alice")

    # # Credentials manager
    # creds = Credentials()

    # # Add a credential (auto-log CREDENTIAL_CREATED)
    # creds.add_credential("bob")

    # # Get a credential (auto-log CREDENTIAL_VIEWED)
    # print("Bob’s credential:", creds.get_credential("bob"))

    # # Rotate a credential (auto-log CREDENTIAL_ROTATED)
    # newpw = creds.rotate_credential("bob")
    # print("Bob’s rotated password:", newpw)

    # # Verify wrong password (auto-log CREDENTIAL_VERIFY_FAILED)
    # print("Verify Bob:", creds.verify_password("bob", "wrongpassword"))

    # # === AuditEvent direct usage ===
    # audit = AuditEvent()

    # # Manually log something (optional)
    # audit.log_event("SYSTEM", "CUSTOM_EVENT", "This is a custom test event")

    # # Show the last 10 audit events
    # print("\n--- Audit Log (last 10) ---")
    # for e in audit.list_events(limit=10):
    #     print(e)

    DataBase().init_db()
    # # Roles().add_role(name="admin",permissions="everything")
    # AccessGrant().grant_access(username="vlupas", role="admin", overrides="Can see and do everything.")
    # # Employees().update_employee(username="vlupas", role="admin")
    # check = AccessGrant().check_access(username="vlupas", permission="everything")
    # print(check)
    # #AccessGrant().revoke_access(username="vlupas")
    current_user = "vlupas"
    emp = Employees(actor=current_user)
    emp.add_employee("alice", dept="IT", role="Engineer")

    creds = Credentials(actor=current_user)
    creds.add_credential("alice")

    res = Resources(actor=current_user)
    res.add_resource("Prod DB", type="Database")

    role = Roles(actor=current_user)
    role.add_role("Admin")

    ag = AccessGrant(actor=current_user)
    ag.grant_access("alice", "Prod DB")
    Employees().soft_delete_employee(username="vlupas")



