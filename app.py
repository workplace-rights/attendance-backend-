from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import hashlib, os, csv, io, math
from datetime import datetime, date
from functools import wraps
import secrets
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
CORS(app, origins="*")

DATABASE_URL = os.environ.get("DATABASE_URL", "")

# ── DB ────────────────────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id              SERIAL PRIMARY KEY,
                emp_id          TEXT UNIQUE NOT NULL,
                name            TEXT NOT NULL,
                dept            TEXT,
                id_last4        TEXT NOT NULL,
                password        TEXT NOT NULL,
                is_active       INTEGER DEFAULT 1,
                device_fp       TEXT,
                device_name     TEXT,
                device_bound_at TEXT,
                created_at      TEXT DEFAULT to_char(now(),'YYYY-MM-DD HH24:MI:SS')
            );
            CREATE TABLE IF NOT EXISTS locations (
                id          SERIAL PRIMARY KEY,
                name        TEXT NOT NULL,
                country     TEXT NOT NULL DEFAULT '',
                timezone    TEXT NOT NULL DEFAULT 'Asia/Taipei',
                latitude    REAL NOT NULL,
                longitude   REAL NOT NULL,
                radius_m    INTEGER NOT NULL DEFAULT 300,
                is_active   INTEGER DEFAULT 1,
                note        TEXT DEFAULT '',
                created_at  TEXT DEFAULT to_char(now(),'YYYY-MM-DD HH24:MI:SS')
            );
            CREATE TABLE IF NOT EXISTS punch_records (
                id            SERIAL PRIMARY KEY,
                emp_id        TEXT NOT NULL,
                punch_type    TEXT NOT NULL,
                punch_time    TEXT NOT NULL,
                latitude      REAL,
                longitude     REAL,
                accuracy      REAL,
                location_id   INTEGER,
                location_name TEXT,
                ip_addr       TEXT,
                device_fp     TEXT,
                device_name   TEXT,
                note          TEXT,
                created_at    TEXT DEFAULT to_char(now(),'YYYY-MM-DD HH24:MI:SS')
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token       TEXT PRIMARY KEY,
                emp_id      TEXT NOT NULL,
                device_fp   TEXT,
                created_at  TEXT DEFAULT to_char(now(),'YYYY-MM-DD HH24:MI:SS')
            );
            """)
            # 管理員帳號
            pw = hash_pw("ADMIN", "0000")
            cur.execute("""
                INSERT INTO employees (emp_id,name,dept,id_last4,password,is_active)
                VALUES (%s,%s,%s,%s,%s,1)
                ON CONFLICT (emp_id) DO NOTHING
            """, ("ADMIN","管理員","管理部","0000",pw))
            # 預設地點
            cur.execute("SELECT COUNT(*) as cnt FROM locations")
            if cur.fetchone()["cnt"] == 0:
                cur.executemany(
                    "INSERT INTO locations(name,country,timezone,latitude,longitude,radius_m,note) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    [
                        ("台灣總部",  "台灣","Asia/Taipei",        25.0375, 121.5637, 300,"台北廠區"),
                        ("越南廠區",  "越南","Asia/Ho_Chi_Minh",   10.8231, 106.6297, 300,"胡志明市廠"),
                        ("泰國廠區",  "泰國","Asia/Bangkok",       13.7563, 100.5018, 300,"曼谷廠"),
                    ]
                )
        conn.commit()

def hash_pw(emp_id, id_last4):
    raw = f"{emp_id}:{id_last4}:attendance_salt_2024"
    return hashlib.sha256(raw.encode()).hexdigest()

def get_client_ip():
    return (request.headers.get("X-Forwarded-For","").split(",")[0].strip()
            or request.remote_addr or "")

def dist_meters(lat1, lng1, lat2, lng2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2-lat1)
    dlam = math.radians(lng2-lng1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

# ── Auth ──────────────────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization","").replace("Bearer ","")
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT emp_id,device_fp FROM sessions WHERE token=%s",(token,))
                row = cur.fetchone()
        if not row:
            return jsonify({"error":"未登入或 session 已過期"}), 401
        request.emp_id  = row["emp_id"]
        request.sess_fp = row["device_fp"] or ""
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization","").replace("Bearer ","")
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT emp_id FROM sessions WHERE token=%s",(token,))
                row = cur.fetchone()
        if not row or row["emp_id"] != "ADMIN":
            return jsonify({"error":"需要管理員權限"}), 403
        return f(*args, **kwargs)
    return wrapper

# ── Login ─────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json or {}
    emp_id   = data.get("emp_id","").strip().upper()
    id_last4 = data.get("id_last4","").strip()
    dfp      = data.get("device_fp","").strip()
    dname    = data.get("device_name","").strip()
    if not emp_id or not id_last4:
        return jsonify({"error":"請輸入員工編號與身分證後4碼"}), 400
    pw = hash_pw(emp_id, id_last4)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM employees WHERE emp_id=%s AND password=%s AND is_active=1",(emp_id,pw))
            emp = cur.fetchone()
    if not emp:
        return jsonify({"error":"帳號或密碼錯誤，或帳號已停用"}), 401
    emp = dict(emp)
    # 裝置綁定
    if emp_id != "ADMIN" and dfp:
        bound = emp.get("device_fp") or ""
        if not bound:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE employees SET device_fp=%s,device_name=%s,device_bound_at=%s WHERE emp_id=%s",
                        (dfp,dname,datetime.now().strftime("%Y-%m-%d %H:%M:%S"),emp_id))
                conn.commit()
            emp["device_fp"]=dfp; emp["device_name"]=dname
        elif bound != dfp:
            return jsonify({"error":"裝置驗證失敗：此帳號已綁定其他裝置，請聯繫管理員解除綁定",
                            "error_code":"DEVICE_MISMATCH"}), 403
    token = secrets.token_hex(32)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE emp_id=%s",(emp_id,))
            cur.execute("INSERT INTO sessions(token,emp_id,device_fp) VALUES(%s,%s,%s)",(token,emp_id,dfp))
        conn.commit()
    return jsonify({
        "token":        token,
        "emp_id":       emp["emp_id"],
        "name":         emp["name"],
        "dept":         emp["dept"],
        "is_admin":     emp["emp_id"]=="ADMIN",
        "device_bound": bool(emp.get("device_fp")),
        "device_name":  emp.get("device_name") or "",
    })

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("Authorization","").replace("Bearer ","")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token=%s",(token,))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/change_password", methods=["POST"])
@require_auth
def change_password():
    data = request.json or {}
    new4 = data.get("new_last4","").strip()
    if len(new4)!=4 or not new4.isalnum():
        return jsonify({"error":"新密碼需為4碼英數字"}), 400
    pw = hash_pw(request.emp_id, new4)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE employees SET id_last4=%s,password=%s WHERE emp_id=%s",(new4,pw,request.emp_id))
        conn.commit()
    return jsonify({"ok":True})

# ── Locations ─────────────────────────────────────────────────────────────
@app.route("/api/locations", methods=["GET"])
@require_auth
def list_locations():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,country,timezone,latitude,longitude,radius_m,note FROM locations WHERE is_active=1 ORDER BY country,name")
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

# ── Punch ─────────────────────────────────────────────────────────────────
@app.route("/api/punch", methods=["POST"])
@require_auth
def punch():
    data       = request.json or {}
    punch_type = data.get("type")
    lat        = data.get("latitude")
    lng        = data.get("longitude")
    acc        = data.get("accuracy")
    dfp        = data.get("device_fp","").strip()
    if punch_type not in ("in","out"):
        return jsonify({"error":"打卡類型錯誤"}), 400
    if lat is None or lng is None:
        return jsonify({"error":"缺少位置資訊"}), 400
    # 裝置驗證
    if request.emp_id != "ADMIN":
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT device_fp FROM employees WHERE emp_id=%s",(request.emp_id,))
                emp = cur.fetchone()
        bound = (emp["device_fp"] or "") if emp else ""
        if bound and dfp and bound != dfp:
            return jsonify({"error":"裝置驗證失敗：打卡裝置與綁定裝置不符","error_code":"DEVICE_MISMATCH"}), 403
    # 地點驗證
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,latitude,longitude,radius_m FROM locations WHERE is_active=1")
            locs = cur.fetchall()
    matched_id, matched_name, matched_dist = None, None, None
    for loc in locs:
        d = dist_meters(lat, lng, loc["latitude"], loc["longitude"])
        if d <= loc["radius_m"]:
            if matched_dist is None or d < matched_dist:
                matched_id=loc["id"]; matched_name=loc["name"]; matched_dist=d
    if matched_id is None:
        nearest = min(locs, key=lambda l: dist_meters(lat,lng,l["latitude"],l["longitude"]), default=None)
        hint=""
        if nearest:
            d = int(dist_meters(lat,lng,nearest["latitude"],nearest["longitude"]))
            hint=f"（最近地點「{nearest['name']}」距離 {d} 公尺）"
        return jsonify({"error":f"不在任何允許打卡的地點範圍內{hint}","error_code":"NOT_IN_LOCATION"}), 403
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    today = date.today().strftime("%Y-%m-%d")
    ip    = get_client_ip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM punch_records WHERE emp_id=%s AND punch_type=%s AND punch_time LIKE %s",
                        (request.emp_id, punch_type, f"{today}%"))
            if cur.fetchone():
                label="上班" if punch_type=="in" else "下班"
                return jsonify({"error":f"今日已有{label}打卡記錄"}), 409
            cur.execute("SELECT device_name FROM employees WHERE emp_id=%s",(request.emp_id,))
            emp_row=cur.fetchone()
            dname_saved=emp_row["device_name"] if emp_row else ""
            cur.execute("""INSERT INTO punch_records
                (emp_id,punch_type,punch_time,latitude,longitude,accuracy,
                 location_id,location_name,ip_addr,device_fp,device_name)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (request.emp_id,punch_type,now,lat,lng,acc,
                 matched_id,matched_name,ip,dfp,dname_saved))
        conn.commit()
    return jsonify({"ok":True,"time":now,"type":punch_type,"location_name":matched_name})

@app.route("/api/punch/today", methods=["GET"])
@require_auth
def punch_today():
    today = date.today().strftime("%Y-%m-%d")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM punch_records WHERE emp_id=%s AND punch_time LIKE %s ORDER BY punch_time",
                        (request.emp_id, f"{today}%"))
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

# ── Admin: Employees ──────────────────────────────────────────────────────
@app.route("/api/admin/employees", methods=["GET"])
@require_admin
def list_employees():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,emp_id,name,dept,id_last4,is_active,device_fp,device_name,device_bound_at,created_at FROM employees ORDER BY emp_id")
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/employees", methods=["POST"])
@require_admin
def add_employee():
    data=request.json or {}
    emp_id=data.get("emp_id","").strip().upper()
    name=data.get("name","").strip()
    dept=data.get("dept","").strip()
    id_last4=data.get("id_last4","").strip()
    if not all([emp_id,name,id_last4]):
        return jsonify({"error":"員工編號、姓名、身分證後4碼為必填"}), 400
    pw=hash_pw(emp_id,id_last4)
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO employees(emp_id,name,dept,id_last4,password) VALUES(%s,%s,%s,%s,%s)",
                            (emp_id,name,dept,id_last4,pw))
            conn.commit()
    except Exception as e:
        if "unique" in str(e).lower():
            return jsonify({"error":f"員工編號 {emp_id} 已存在"}), 409
        return jsonify({"error":str(e)}), 500
    return jsonify({"ok":True})

@app.route("/api/admin/employees/<emp_id>/toggle", methods=["POST"])
@require_admin
def toggle_employee(emp_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT is_active FROM employees WHERE emp_id=%s",(emp_id,))
            row=cur.fetchone()
            if not row: return jsonify({"error":"找不到此員工"}), 404
            ns=0 if row["is_active"] else 1
            cur.execute("UPDATE employees SET is_active=%s WHERE emp_id=%s",(ns,emp_id))
        conn.commit()
    return jsonify({"ok":True,"is_active":ns})

@app.route("/api/admin/employees/<emp_id>/reset_password", methods=["POST"])
@require_admin
def reset_password(emp_id):
    data=request.json or {}
    new4=data.get("id_last4","").strip()
    if not new4: return jsonify({"error":"請提供新的身分證後4碼"}), 400
    pw=hash_pw(emp_id,new4)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE employees SET id_last4=%s,password=%s WHERE emp_id=%s",(new4,pw,emp_id))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/employees/<emp_id>/unbind_device", methods=["POST"])
@require_admin
def unbind_device(emp_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT emp_id FROM employees WHERE emp_id=%s",(emp_id,))
            if not cur.fetchone(): return jsonify({"error":"找不到此員工"}), 404
            cur.execute("UPDATE employees SET device_fp=NULL,device_name=NULL,device_bound_at=NULL WHERE emp_id=%s",(emp_id,))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/import", methods=["POST"])
@require_admin
def import_employees():
    data=request.json or {}
    rows=data.get("rows",[])
    success,failed=0,[]
    with get_db() as conn:
        with conn.cursor() as cur:
            for r in rows:
                emp_id=str(r.get("emp_id","")).strip().upper()
                name=str(r.get("name","")).strip()
                dept=str(r.get("dept","")).strip()
                id_last4=str(r.get("id_last4","")).strip()
                if not all([emp_id,name,id_last4]):
                    failed.append({"row":r,"reason":"缺少必要欄位"}); continue
                pw=hash_pw(emp_id,id_last4)
                try:
                    cur.execute("""INSERT INTO employees(emp_id,name,dept,id_last4,password)
                        VALUES(%s,%s,%s,%s,%s)
                        ON CONFLICT(emp_id) DO UPDATE SET
                        name=EXCLUDED.name,dept=EXCLUDED.dept,
                        id_last4=EXCLUDED.id_last4,password=EXCLUDED.password""",
                        (emp_id,name,dept,id_last4,pw))
                    success+=1
                except Exception as e:
                    failed.append({"row":r,"reason":str(e)})
        conn.commit()
    return jsonify({"success":success,"failed":failed})

# ── Admin: Locations ──────────────────────────────────────────────────────
@app.route("/api/admin/locations", methods=["GET"])
@require_admin
def admin_list_locations():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM locations ORDER BY country,name")
            rows=cur.fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/locations", methods=["POST"])
@require_admin
def admin_add_location():
    data=request.json or {}
    name=data.get("name","").strip()
    country=data.get("country","").strip()
    tz=data.get("timezone","Asia/Taipei").strip()
    note=data.get("note","").strip()
    try:
        lat=float(data.get("latitude",0))
        lng=float(data.get("longitude",0))
        rad=int(data.get("radius_m",300))
    except (TypeError,ValueError):
        return jsonify({"error":"座標或半徑格式錯誤"}), 400
    if not name or not country: return jsonify({"error":"地點名稱與國家為必填"}), 400
    if not(-90<=lat<=90) or not(-180<=lng<=180): return jsonify({"error":"GPS座標超出範圍"}), 400
    if rad<10 or rad>50000: return jsonify({"error":"允許半徑需在 10–50000 公尺之間"}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO locations(name,country,timezone,latitude,longitude,radius_m,note) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                        (name,country,tz,lat,lng,rad,note))
            loc=cur.fetchone()
        conn.commit()
    return jsonify(dict(loc))

@app.route("/api/admin/locations/<int:loc_id>", methods=["PUT"])
@require_admin
def admin_update_location(loc_id):
    data=request.json or {}
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM locations WHERE id=%s",(loc_id,))
            row=cur.fetchone()
            if not row: return jsonify({"error":"找不到此地點"}), 404
            row=dict(row)
            name=data.get("name",row["name"])
            country=data.get("country",row["country"])
            tz=data.get("timezone",row["timezone"])
            note=data.get("note",row["note"])
            try:
                lat=float(data.get("latitude",row["latitude"]))
                lng=float(data.get("longitude",row["longitude"]))
                rad=int(data.get("radius_m",row["radius_m"]))
            except (TypeError,ValueError):
                return jsonify({"error":"座標或半徑格式錯誤"}), 400
            cur.execute("UPDATE locations SET name=%s,country=%s,timezone=%s,latitude=%s,longitude=%s,radius_m=%s,note=%s WHERE id=%s",
                        (name,country,tz,lat,lng,rad,note,loc_id))
            cur.execute("SELECT * FROM locations WHERE id=%s",(loc_id,))
            updated=cur.fetchone()
        conn.commit()
    return jsonify(dict(updated))

@app.route("/api/admin/locations/<int:loc_id>/toggle", methods=["POST"])
@require_admin
def admin_toggle_location(loc_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT is_active FROM locations WHERE id=%s",(loc_id,))
            row=cur.fetchone()
            if not row: return jsonify({"error":"找不到此地點"}), 404
            ns=0 if row["is_active"] else 1
            cur.execute("UPDATE locations SET is_active=%s WHERE id=%s",(ns,loc_id))
        conn.commit()
    return jsonify({"ok":True,"is_active":ns})

@app.route("/api/admin/locations/<int:loc_id>", methods=["DELETE"])
@require_admin
def admin_delete_location(loc_id):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM locations WHERE id=%s",(loc_id,))
            if not cur.fetchone(): return jsonify({"error":"找不到此地點"}), 404
            cur.execute("SELECT COUNT(*) as cnt FROM punch_records WHERE location_id=%s",(loc_id,))
            used=cur.fetchone()["cnt"]
            if used>0: return jsonify({"error":f"此地點已有 {used} 筆打卡記錄，無法刪除，請改為停用"}), 409
            cur.execute("DELETE FROM locations WHERE id=%s",(loc_id,))
        conn.commit()
    return jsonify({"ok":True})

# ── Admin: Records & Export ───────────────────────────────────────────────
@app.route("/api/admin/records", methods=["GET"])
@require_admin
def admin_records():
    start=request.args.get("start","")
    end=request.args.get("end","")
    dept=request.args.get("dept","")
    loc_id=request.args.get("location_id","")
    q="SELECT r.*,e.name,e.dept FROM punch_records r JOIN employees e ON r.emp_id=e.emp_id WHERE 1=1"
    params=[]
    if start:  q+=" AND r.punch_time >= %s"; params.append(start)
    if end:    q+=" AND r.punch_time <= %s"; params.append(end+" 23:59:59")
    if dept:   q+=" AND e.dept = %s";        params.append(dept)
    if loc_id: q+=" AND r.location_id = %s"; params.append(loc_id)
    q+=" ORDER BY r.punch_time DESC LIMIT 500"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(q,params)
            rows=cur.fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/export_csv", methods=["GET"])
@require_admin
def export_csv():
    start=request.args.get("start","")
    end=request.args.get("end","")
    loc_id=request.args.get("location_id","")
    q="SELECT e.emp_id,e.name,e.dept,r.punch_type,r.punch_time,r.latitude,r.longitude,r.location_name,r.ip_addr,r.device_name FROM punch_records r JOIN employees e ON r.emp_id=e.emp_id WHERE 1=1"
    params=[]
    if start:  q+=" AND r.punch_time >= %s"; params.append(start)
    if end:    q+=" AND r.punch_time <= %s"; params.append(end+" 23:59:59")
    if loc_id: q+=" AND r.location_id = %s"; params.append(loc_id)
    q+=" ORDER BY r.punch_time DESC"
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(q,params)
            rows=cur.fetchall()
    output=io.StringIO()
    w=csv.writer(output)
    w.writerow(["員工編號","姓名","部門","打卡類型","打卡時間","打卡地點","緯度","經度","IP位址","打卡裝置"])
    for r in rows:
        w.writerow([r["emp_id"],r["name"],r["dept"],
                    "上班" if r["punch_type"]=="in" else "下班",
                    r["punch_time"],r["location_name"] or "",
                    r["latitude"],r["longitude"],r["ip_addr"] or "",r["device_name"] or ""])
    return Response("\ufeff"+output.getvalue(), mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition":"attachment; filename=attendance.csv"})

@app.route("/api/admin/depts", methods=["GET"])
@require_admin
def list_depts():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT dept FROM employees WHERE dept!='' ORDER BY dept")
            rows=cur.fetchall()
    return jsonify([r["dept"] for r in rows])

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status":"ok","message":"打卡系統 API 運行中"})

if __name__ == "__main__":
    init_db()
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port,debug=False)
