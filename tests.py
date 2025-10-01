import unittest
from mockdb import DataBase, Employees, Roles, Resources, Credentials, AccessGrant, AuditEvent


class TestDatabase(unittest.TestCase):

    def setUp(self):
        # Fresh DB before each test
        self.db = DataBase()
        self.db.init_db()

    # === EMPLOYEES ===
    def test_add_employee(self):
        emp = Employees(actor="TESTER")
        emp.add_employee("alice", name="Alice", dept="IT", role="Engineer", salary=5000, status="active")
        conn = self.db.get_connection()
        row = conn.execute("SELECT * FROM Employees WHERE username='alice'").fetchone()
        conn.close()
        self.assertIsNotNone(row)

    def test_add_duplicate_employee(self):
        emp = Employees(actor="TESTER")
        emp.add_employee("bob", dept="HR")
        result = emp.add_employee("bob", dept="HR")  # duplicate
        self.assertFalse(result)

    def test_update_employee(self):
        emp = Employees(actor="TESTER")
        emp.add_employee("carol", dept="Finance", salary=2000)
        emp.update_employee("carol", salary=3000)
        conn = self.db.get_connection()
        row = conn.execute("SELECT salary FROM Employees WHERE username='carol'").fetchone()
        conn.close()
        self.assertEqual(row["salary"], 3000)

    def test_soft_delete_and_undo_employee(self):
        emp = Employees(actor="TESTER")
        emp.add_employee("dan", dept="Legal")
        emp.soft_delete_employee("dan")
        conn = self.db.get_connection()
        row = conn.execute("SELECT status FROM Employees WHERE username='dan'").fetchone()
        self.assertEqual(row["status"], "deleted")
        emp.undo_delete_employee("dan")
        row = conn.execute("SELECT status FROM Employees WHERE username='dan'").fetchone()
        conn.close()
        self.assertEqual(row["status"], "active")

    # === ROLES ===
    def test_add_and_update_role(self):
        role = Roles(actor="TESTER")
        role.add_role("admin", permissions="read,write")
        role.update_role(name="admin", permissions="read,write,delete")
        conn = self.db.get_connection()
        row = conn.execute("SELECT permissions FROM Roles WHERE name='admin'").fetchone()
        conn.close()
        self.assertIn("delete", row["permissions"])

    # === RESOURCES ===
    def test_add_and_delete_resource(self):
        res = Resources(actor="TESTER")
        res.add_resource("Prod DB", type="Database", owner_dept="IT")
        conn = self.db.get_connection()
        row = conn.execute("SELECT * FROM Resources WHERE name='Prod DB'").fetchone()
        self.assertIsNotNone(row)
        res.del_resource(row["id"], owner_dept="IT")
        row2 = conn.execute("SELECT * FROM Resources WHERE id=?", (row["id"],)).fetchone()
        conn.close()
        self.assertIsNone(row2)

    # === CREDENTIALS ===
    def test_add_and_get_credential(self):
        creds = Credentials(actor="TESTER")
        creds.add_credential("eve", password="mypassword")
        pw = creds.get_credential("eve")
        self.assertEqual(pw, "mypassword")

    def test_rotate_credential(self):
        creds = Credentials(actor="TESTER")
        creds.add_credential("frank", password="start123")
        newpw = creds.rotate_credential("frank")
        self.assertNotEqual(newpw, "start123")
        self.assertTrue(creds.verify_password("frank", newpw))

    def test_verify_wrong_password(self):
        creds = Credentials(actor="TESTER")
        creds.add_credential("gina", password="correct")
        result = creds.verify_password("gina", "wrong")
        self.assertFalse(result)

    def test_check_expiring_credentials(self):
        creds = Credentials(actor="TESTER")
        creds.add_credential("harry", password="temp123")
        expiring = creds.check_expiring_credentials(days=2000)  # should include harry
        usernames = [e["username"] for e in expiring]
        self.assertIn("harry", usernames)

    def test_update_password(self):
        creds = Credentials(actor="TESTER")
        creds.add_credential("kate", password="oldpass")
        creds.update_password("kate", "newpass123")
        self.assertTrue(creds.verify_password("kate", "newpass123"))

    # === ACCESS GRANT ===
    def test_grant_and_check_access(self):
        emp = Employees(actor="TESTER")
        emp.add_employee("ivy", dept="IT")

        role = Roles(actor="TESTER")
        role.add_role("reader", permissions="read")

        ag = AccessGrant(actor="TESTER")
        ag.grant_access("ivy", "reader")
        self.assertTrue(ag.check_access("ivy", "read"))
        self.assertFalse(ag.check_access("ivy", "write"))

    def test_revoke_access(self):
        emp = Employees(actor="TESTER")
        emp.add_employee("john", dept="HR")

        role = Roles(actor="TESTER")
        role.add_role("editor", permissions="write")

        ag = AccessGrant(actor="TESTER")
        ag.grant_access("john", "editor")
        ag.revoke_access("john")
        self.assertFalse(ag.check_access("john", "write"))

    # === AUDIT ===
    def test_audit_logging(self):
        audit = AuditEvent()
        audit.log_event("TESTER", "UNITTEST_EVENT", "Checking audit log")
        logs = audit.list_events(limit=1)
        self.assertEqual(logs[0]["action"], "UNITTEST_EVENT")

    def test_list_audit_events(self):
        audit = AuditEvent()
        audit.log_event("TESTER", "LIST_TEST", "Testing list_events")
        events = audit.list_events(limit=5)
        actions = [e["action"] for e in events]
        self.assertIn("LIST_TEST", actions)

if __name__ == "__main__":
    unittest.main()
