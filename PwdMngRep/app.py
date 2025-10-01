import streamlit as st
import pandas as pd
from mockdb import DataBase, Employees, Roles, Resources, Credentials, AccessGrant, AuditEvent
import sqlite3

DataBase().init_db()

# ---------- STATE ----------
if "user" not in st.session_state:
    st.session_state["user"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None
    

# ---------- HELPER DB ----------
def get_user_role(username):
    conn = Employees().get_connection()
    r = conn.execute("SELECT role FROM Employees WHERE username=?", (username,)).fetchone()
    conn.close()
    return r["role"] if r else None

def add_signup_request(username, password, name, dept, role):
    conn = Employees().get_connection()
    try:
        conn.execute("""
            INSERT INTO SignupRequests (username, password_hash, name, dept, role)
            VALUES (?, ?, ?, ?, ?)
        """, (username, password, name, dept, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def list_signup_requests():
    conn = Employees().get_connection()
    rows = conn.execute("SELECT * FROM SignupRequests WHERE status='pending'").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def approve_request(req_id):
    conn = Employees().get_connection()
    row = conn.execute("SELECT * FROM SignupRequests WHERE id=?", (req_id,)).fetchone()
    if not row:
        return False
    
    # Adaugă userul în Employees
    Employees().add_employee(username=row["username"], name=row["name"], dept=row["dept"],
                             role=row["role"], status="active")

    # Salvează parola în Credentials (criptată)
    cred = Credentials(actor="SYSTEM")
    cred.add_credential(row["username"], password=row["password_hash"])

    conn.execute("UPDATE SignupRequests SET status='approved' WHERE id=?", (req_id,))
    conn.commit()
    conn.close()
    return True

def discard_request(req_id):
    conn = Employees().get_connection()
    conn.execute("UPDATE SignupRequests SET status='discarded' WHERE id=?", (req_id,))
    conn.commit()
    conn.close()

# ---------- PAGES ----------
def login_page():
    st.title("🔐 Login")
    u = st.text_input("Username", key="login_username")
    p = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", key="login_btn"):
        conn = Employees().get_connection()
        row = conn.execute(
            "SELECT * FROM Employees WHERE username=? AND status='active'", (u,)
        ).fetchone()
        conn.close()
        if row:
            # verifică parola prin Credentials
            cred = Credentials(actor="SYSTEM")
            if cred.verify_password(u, p):
                st.session_state.user = u
                st.session_state.role = row["role"]
                st.success(f"Bun venit {u} ({row['role']})!")
                st.rerun()
            else:
                st.error("Parolă greșită.")
        else:
            st.error("User inexistent sau inactiv.")

def signup_page():
    st.title("🆕 Cerere cont")
    u = st.text_input("Username", key="signup_username")
    p = st.text_input("Password", type="password", key="signup_password")
    n = st.text_input("Nume complet", key="signup_name")
    d = st.text_input("Departament", key="signup_dept")
    r = st.selectbox("Rol dorit", Roles().show_roles(), key="signup_role")
    if st.button("Trimite cerere", key="signup_btn"):   # <--- key adăugat
        if add_signup_request(u, p, n, d, r):
            st.success("Cererea a fost trimisă. Un manager trebuie să o aprobe.")
        else:
            st.error("Username deja folosit sau eroare.")

def employees_page():
    st.header("👥 Employees")
    st.dataframe([dict(r) for r in  Employees().show_employees()])

def edit_profile():
    st.subheader("✏️ Edit Profile")
    emp = Employees()
    conn = emp.get_connection()

    # ia toți userii din Employees
    all_users = [r["username"] for r in conn.execute("SELECT username FROM Employees").fetchall()]
    conn.close()

    if not all_users:
        st.warning("Nu există utilizatori în baza de date.")
        return

    # dropdown pentru selectarea userului
    username = st.selectbox("Selectează utilizator", all_users)

    # încarcă datele userului selectat
    conn = emp.get_connection()
    row = conn.execute("SELECT * FROM Employees WHERE username=?", (username,)).fetchone()
    conn.close()

    if not row:
        st.error("User negăsit")
        return

    # câmpuri editabile
    n = st.text_input("Name", row["name"])
    d = st.text_input("Department", row["dept"])
    r = st.text_input("Role", row["role"])
    if  "deleted" not in row["status"]:
        stt = st.selectbox("Status", ["active", "inactive", "on leave"], index=["active", "inactive", "on leave"].index(row["status"]), key="status_select")
    s = st.number_input("Salary", min_value=0, value=row["salary"] if row["salary"] else 0, step=100)

    if st.button("💾 Save"):
        ok = emp.update_employee(username, name=n, dept=d, role=r, salary=s, status=stt if stt else None)
        if ok:
            st.success(f"Profilul {username} a fost actualizat.")
        else:
            st.error("Eroare la actualizare.")
        st.rerun()

    # --- Soft Delete & Undo Delete ---
    st.markdown("---")
    st.subheader("⚠️ Soft Delete action")
    st.markdown(
        """
        Soft delete will **not remove the employee record permanently**.  
        Instead, the employee will be marked as `deleted` and hidden from normal operations.  
        You can **restore this employee later** using the *Undo Delete* button.  

        ✅ Use this if you want to temporarily disable an employee without losing their history.  
        ❌ If you need to remove data permanently, you must perform a hard delete (not recommended in most cases).
        """
    )

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🗑️ Soft Delete Employee", disabled=("deleted" in str(row["status"]))):
            try:
                emp.soft_delete_employee(username)
                # salvează notificarea în session_state
                st.session_state["notif"] = ("warning", f"Employee **{username}** was soft deleted (status set to 'deleted').")
                st.rerun()
            except Exception as e:
                st.session_state["notif"] = ("error", f"Error while soft deleting employee: {e}")
                st.rerun()

    with col2:
        if st.button("↩️ Undo Delete", disabled=("deleted" not in str(row["status"]))):
            try:
                emp.undo_delete_employee(username)
                st.session_state["notif"] = ("success", f"Employee **{username}** was restored (status set to 'active').")
                st.rerun()
            except Exception as e:
                st.session_state["notif"] = ("error", f"Error while undoing delete: {e}")
                st.rerun()

    # --- Afișare notificare dacă există ---
    if "notif" in st.session_state:
        level, msg = st.session_state["notif"]
        if level == "success":
            st.success(msg)
        elif level == "warning":
            st.warning(msg)
        elif level == "error":
            st.error(msg)


def grant_access_page():
    st.subheader("Grant Access")
    access = AccessGrant()
    conn = Employees().get_connection()
    all_users = [r["username"] for r in conn.execute("SELECT username FROM Employees").fetchall()]
    conn.close()
    user = st.selectbox("Selectează utilizator", all_users)
    role = st.text_input("Rol pentru grant")
    over = st.text_input("Overrides")
    if st.button("Grant"):
        access.grant_access(user, role, over)
        st.success("Access granted.")
        st.rerun()

    st.dataframe([dict(r) for r in  AccessGrant().show_access_grants()])

def resources_page(view_all=False):
    st.subheader("Resources")
    res = Resources()

    # --- Listare resources ---
    st.markdown("### 📋 All Resources")
    conn = res.get_connection()
    rows = conn.execute("SELECT * FROM Resources").fetchall()
    conn.close()
    if rows:
        df = pd.DataFrame([dict(r) for r in rows])
        df.index = [""] * len(df)   # elimină etichetele indexului
        st.table(df)
    else:
        st.info("No resources found.")

    # --- Adaugă resource ---
    st.markdown("### ➕ Add Resource")
    rn = st.text_input("Resource Name")
    rt = st.text_input("Type")
    od = st.text_input("Owner Dept")
    if st.button("Add Resource"):
        res.add_resource(rn, rt, od)
        st.success(f"Resource '{rn}' added.")
        st.rerun()

    st.divider()

    # --- Șterge resource ---
    st.markdown("### 🗑️ Delete Resource")
    all_resources = res.show_resources()
    if all_resources:
        del_rn = st.selectbox("Select Resource to delete", all_resources, key="del_res")
        od_del = st.text_input("Owner Dept (for validation)", key="del_dept")
        if st.button("Delete Resource"):
            ok = res.del_resource(del_rn, od_del)
            if ok:
                st.success(f"Resource '{del_rn}' deleted.")
                st.rerun()
            else:
                st.error("Resource not found or dept mismatch.")
    else:
        st.info("No resources available to delete.")

    st.divider()

    # --- Update resource ---
    st.markdown("### ✏️ Update Resource")
    if all_resources:
        upd_rn = st.selectbox("Select Resource to update", all_resources, key="upd_res")
        new_name = st.text_input("New Name (leave blank to keep)", key="upd_name")
        new_type = st.text_input("New Type (leave blank to keep)", key="upd_type")
        new_dept = st.text_input("New Owner Dept (leave blank to keep)", key="upd_dept")

        if st.button("Update Resource"):
            ok = res.update_resource(
                id = upd_rn,
                name=new_name if new_name else None,
                type=new_type if new_type else None,
                owner_dept=new_dept if new_dept else None
            )
            if ok:
                st.success(f"Resource '{upd_rn}' updated.")
                st.rerun()
            else:
                st.error("Resource not found or no changes made.")
    else:
        st.info("No resources available to update.")

    st.divider()

def signup_requests_page():
    st.header("Account Requests")
    reqs = list_signup_requests()
    for r in reqs:
        with st.expander(f"{r['username']} ({r['role']})"):
            st.write(f"Nume: {r['name']}, Dept: {r['dept']}")
            c1, c2 = st.columns(2)
            if c1.button("Approve", key=f"a{r['id']}"):
                approve_request(r["id"])
                st.success("Aprobat")
                st.rerun()
            if c2.button("Discard", key=f"d{r['id']}"):
                discard_request(r["id"])
                st.warning("Respins")
                st.rerun()

def audit_logs_page():
    st.header("📜 Audit Logs")
    st.dataframe(AuditEvent().list_events(100))

def view_profile_info():
    st.subheader("My Profile")
    
    conn = Employees().get_connection()
    row = conn.execute("SELECT * FROM Employees WHERE username=?", (st.session_state.user,)).fetchone()
    conn.close()
    
    if row:
        profile = dict(row)
        
        st.markdown("### Personal Info")
        st.markdown(f"**Name:** {profile.get('name', 'N/A')}")
        st.markdown(f"**Department:** {profile.get('dept', 'N/A')}")
        st.markdown(f"**Role:** {profile.get('role', 'N/A')}")
        st.markdown(f"**Salary:** {profile.get('salary', 'N/A')}")
    
        st.divider()
        st.markdown("### Alte informații")
        st.markdown(f"**Username:** {profile.get('username', 'N/A')}")
        st.markdown(f"**Account Status:** {profile.get('status', 'N/A')}")
     
        cred = Credentials(actor=st.session_state.user)
        
        st.divider()
        st.markdown("### Change Password")
        current_pw = st.text_input("Current Password", type="password", key="current_pw")
        new_pw = st.text_input("New Password", type="password", key="new_pw")
        if st.button("Change Password"):
            if cred.verify_password(st.session_state.user, current_pw):
                cred.update_password(st.session_state.user, new_pw)
                st.success("Password updated successfully.")
            else:
                st.error("Old password is incorrect.")
        
        st.divider()
        st.markdown("### Check Expiring Credential")
        if st.button("Check Expiring Credential"):
            exp_cred = cred.check_time_remaining(st.session_state.user)
            if exp_cred:
                st.warning(f"Your credential is expiring on {exp_cred} days. Please update it soon.")
            else:
                st.success("No expiring credentials found.")
        
        st.divider()
        st.markdown("### View Credential")
        if st.button("View Credential"):
            pw = cred.view_credential(st.session_state.user, st.session_state.user)
            if pw:
                st.info(f"Your credential password is: {pw}")
            else:
                st.error("Could not retrieve credential.")

    else:
        st.error("Profil negăsit.")

def view_expiring_credentials_page():
    st.markdown("### Employees with Expiring Credentials")
    remaining_days = st.text_input("Insert the remaining days until the expiration date", key="remaining_days")
    if st.button("Check Expiring Credentials"):
        cred = Credentials(actor=st.session_state.user)
        expiring = cred.check_expiring_credentials(days=int(remaining_days))
        if expiring:
            df = pd.DataFrame([dict(r) for r in expiring])
            df = df.rename(columns={
                "id": "id",
                "username": "username",
                "created_at": "creation date",
                "rotation_date": "rotation date"
            })
            df.index = [""] * len(df)   # elimină etichetele indexului
            st.dataframe(df)

def credentials_employees_page():
    st.title("🔑 Employee Credentials")
    st.markdown("Browse and explore employee credentials in a clean and interactive way.")

    # Get the data
    raw_data = [dict(r) for r in Credentials().list_credentials()]
    df = pd.DataFrame(raw_data)

    if df.empty:
        st.warning("⚠️ No credentials available at the moment.")
        return

    # --- Filters above the table ---
    st.subheader("🔍 Filters")
    col1, col2, col3 = st.columns([2, 2, 1])

    with col1:
        search_term = st.text_input("Search (any field):")

    with col2:
        filter_col = st.selectbox("Filter by column:", options=["None"] + list(df.columns))

    with col3:
        filter_val = ""
        if filter_col != "None":
            filter_val = st.text_input(f"{filter_col} contains:")

    # Apply filters
    filtered_df = df.copy()
    if search_term:
        mask = df.apply(lambda row: row.astype(str).str.contains(search_term, case=False).any(), axis=1)
        filtered_df = filtered_df[mask]

    if filter_col != "None" and filter_val:
        filtered_df = filtered_df[filtered_df[filter_col].astype(str).str.contains(filter_val, case=False)]

    # Display info
    st.info(f"📊 Total credentials: **{len(df)}** | Showing **{len(filtered_df)}** after filters")

    # Display table
    st.dataframe(filtered_df)

    # Download button
    csv = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download as CSV",
        data=csv,
        file_name="credentials.csv",
        mime="text/csv",
    )

    # ---------------------------
    # Password reveal UI
    # ---------------------------
    st.markdown("---")
    st.subheader("🔐 View password (requires confirmation)")

    # Collect usernames for selection (if username column exists)
    username_col = None
    for cand in ["username", "user", "login"]:
        if cand in df.columns:
            username_col = cand
            break

    if not username_col:
        st.error("No username column found in credentials table. Cannot fetch a specific user's password.")
        return

    usernames = sorted(df[username_col].astype(str).unique().tolist())
    selected_username = st.selectbox("Select username:", options=["-- select user --"] + usernames)

    st.caption("`IMPORTANT: Fetching a password will decrypts the stored password and logs an audit event.`")

    confirm = st.checkbox("I confirm I have permission to view this credential (audit will be recorded).")

    fetch_col1, fetch_col2 = st.columns([1, 1])
    with fetch_col1:
        fetch_btn = st.button("🔎 Fetch password", disabled=(selected_username == "-- select user --" or not confirm))
    with fetch_col2:
        clear_btn = st.button("🧹 Clear fetched password")

    # Initialize session_state storage for fetched password
    if "fetched_pw_for" not in st.session_state:
        st.session_state["fetched_pw_for"] = None
    if "fetched_pw_value" not in st.session_state:
        st.session_state["fetched_pw_value"] = None
    if "fetched_pw_error" not in st.session_state:
        st.session_state["fetched_pw_error"] = None

    # Clear action
    if clear_btn:
        st.session_state["fetched_pw_for"] = None
        st.session_state["fetched_pw_value"] = None
        st.session_state["fetched_pw_error"] = None
        st.success("Cleared fetched password from this session.")

    # Fetch action: call your Credentials.get_credential(username)
    if fetch_btn:
        try:
            # Call your method which decrypts and logs the audit event
            pw = Credentials().view_credential(selected_username, st.session_state.user)
            if pw is None:
                st.session_state["fetched_pw_for"] = None
                st.session_state["fetched_pw_value"] = None
                st.session_state["fetched_pw_error"] = f"No credential found for user '{selected_username}'."
            else:
                st.session_state["fetched_pw_for"] = selected_username
                st.session_state["fetched_pw_value"] = pw
                st.session_state["fetched_pw_error"] = None
                st.success(f"Password fetched for user: **{selected_username}** (audit recorded).")
        except Exception as e:
            st.session_state["fetched_pw_for"] = None
            st.session_state["fetched_pw_value"] = None
            st.session_state["fetched_pw_error"] = f"Error fetching password: {e}"

    # Show fetched password area (if any)
    if st.session_state.get("fetched_pw_for"):
        st.markdown(f"**Fetched credential for:** `{st.session_state['fetched_pw_for']}`")
        if st.session_state.get("fetched_pw_error"):
            st.error(st.session_state["fetched_pw_error"])
        else:
            # By default masked; provide toggle to reveal
            show_pw = st.checkbox("Show password", value=False, key=f"show_pw_{st.session_state['fetched_pw_for']}")
            pw_value = st.session_state.get("fetched_pw_value", "")
            # Use a text_input so user can copy easily; switch type based on show_pw
            input_type = "default" if show_pw else "password"
            st.text_input("Password (copy it if needed):", value=pw_value, type=input_type, key=f"pw_input_{st.session_state['fetched_pw_for']}")

            # Optional: small note about sensitivity
            st.caption("This password is sensitive. Do not share unless authorized. Audit entry was created at fetch time.")
    else:
        if st.session_state.get("fetched_pw_error"):
            st.error(st.session_state["fetched_pw_error"])
        else:
            st.info("No password fetched in this session. Select a user and click 'Fetch password' to retrieve it (will be logged).")

def backup_database_page():
    st.header("💾 Database Backup")

    st.markdown(
        """
        Here you can create a backup of the database.  
        The backup will be saved in the same folder as the current database.
        """
    )

    if st.button("Create Backup"):
        try:
            db = DataBase()
            db.add_backup()  # uses the method from DataBase class
            st.success("✅ Backup created successfully!")
        except Exception as e:
            st.error(f"❌ Error while creating backup: {e}")


# ---------- DASHBOARD ----------
def dashboard():
    role = st.session_state.role
    st.sidebar.write(f"👤 {st.session_state.user} | Role: {role}")

    if role == "admin":
        menu = ["My Profile", "Employees", "Employees Credentials", "Grant Access", "Resources", "Audit Logs" , "Account Requests", "Database Backup", "Logout"]
    elif role == "manager":
        menu = ["My Profile","Account Requests", "Employees", "Employees Credentials", "Grant Access", "Resources", "Audit Logs", "Logout"]
    elif role == "hr":
        menu = ["My Profile", "Employees", "Edit Employee Profiles", "View Expiring Credentials","Grant Access", "Resources", "Logout"]
    elif role == "employee":
        menu = ["My Profile", "Resources", "View Roles", "Logout"]

    choice = st.sidebar.radio("Navigate", menu)

    if choice == "Logout":
        st.session_state.user = None
        st.session_state.role = None
        st.rerun()
    elif choice == "My Profile":
        view_profile_info()
    elif choice == "Employees Credentials":
        credentials_employees_page()
    elif choice == "Employees":
        employees_page()
    elif choice == "Edit Employee Profiles":
        edit_profile()
    elif choice == "View Expiring Credentials":
        view_expiring_credentials_page()
    elif choice == "Grant Access":
        grant_access_page()
    elif choice == "Resources":
        resources_page(view_all=(role in ["hr", "admin", "manager"]))
    elif choice == "Audit Logs":
        audit_logs_page()
    elif choice == "Account Requests":
        signup_requests_page()
    elif choice == "View Roles":
        conn = Employees().get_connection()
        rows = conn.execute("SELECT username, name, role FROM Employees").fetchall()
        conn.close()
        # transformăm în DataFrame și redenumim coloanele
        df = pd.DataFrame([dict(r) for r in rows])
        df = df.rename(columns={
            "username": "username",
            "name": "name",
            "role": "role"
        })
        st.table(df)
    elif choice == "Database Backup":
        backup_database_page()

# ---------- MAIN ----------
if not st.session_state.user:
    tab1, tab2 = st.tabs(["Login", "Signup"])
    with tab1: login_page()
    with tab2: signup_page()
    # st.markdown(st.session_state.user)
else:
    dashboard()
