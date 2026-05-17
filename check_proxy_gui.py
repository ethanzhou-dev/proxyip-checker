#!/usr/bin/env python3
"""
ProxyIP Checker GUI
DNS: Cloudflare DoH (A/AAAA/TXT)
探测: TCP→TLS→HTTP 验证连通性
位置: ip-api.com 查询代理IP地理位置
"""
import concurrent.futures, json, re, socket, ssl, threading, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.parse import quote
from urllib.error import URLError

CF_PORTS = [443,8443,2053,2083,2087,2096,80,8080,8880,2052,2082,2086,2095]
PROBE_HOST = "ipv4.090227.xyz"
DOH_URL = "https://cloudflare-dns.com/dns-query"
GEO_API = "http://ip-api.com/json/{ip}?fields=status,countryCode,city,isp,org"

_geo_cache = {}
_geo_lock = threading.Lock()

@dataclass
class Result:
    input_addr: str
    resolved_target: str = ""
    ip: str = ""
    port: int = 443
    ok: bool = False
    proxy_country: str = ""
    proxy_city: str = ""
    proxy_isp: str = ""
    exit_ip: str = ""
    exit_colo: str = ""
    exit_org: str = ""
    connect_ms: int = -1
    tls_ms: int = -1
    http_ms: int = -1
    error: str = ""

def doh_query(name, qtype):
    url = f"{DOH_URL}?name={quote(name)}&type={quote(qtype)}"
    try:
        with urlopen(Request(url, headers={"accept":"application/dns-json"}), timeout=8) as r:
            return json.loads(r.read()).get("Answer", [])
    except Exception:
        return []

def is_ipv4(s):
    try: socket.inet_aton(s); return True
    except OSError: return False

def handle_resolve(input_str):
    raw = input_str.split("#")[0].strip()
    if not raw: return []
    port, host = 443, raw
    if host.startswith("["):
        m = re.match(r'^\[([^\]]+)\](?::(\d+))?$', host)
        if m:
            host = m.group(1)
            if m.group(2): port = int(m.group(2))
    elif ":" in host:
        parts = host.rsplit(":", 1)
        if parts[1].isdigit(): host, port = parts[0], int(parts[1])
    tp = re.search(r'\.tp(\d{1,5})\.', host.lower())
    if tp:
        p = int(tp.group(1))
        if 1 <= p <= 65535: port = p
    bv6 = host.startswith("[") and host.endswith("]")
    rv6 = bool(re.match(r'^[0-9a-fA-F:]+$', host))
    if is_ipv4(host) or bv6 or rv6:
        f = f"[{host}]" if rv6 and not bv6 else host
        return [(f"{f}:{port}", host.strip("[]"), port)]
    txt = doh_query(host, "TXT")
    a = doh_query(host, "A")
    aaaa = doh_query(host, "AAAA")
    results, seen = [], set()
    for rec in txt:
        if rec.get("type") == 16 and rec.get("data"):
            for part in rec["data"].strip('"').replace('\\"','"').split(","):
                c = part.strip()
                if c and c not in seen:
                    seen.add(c)
                    results.extend(handle_resolve(c))
    for rec in a:
        if rec.get("type") == 1 and rec.get("data"):
            k = f"{rec['data']}:{port}"
            if k not in seen: seen.add(k); results.append((k, rec["data"], port))
    for rec in aaaa:
        if rec.get("type") == 28 and rec.get("data"):
            k = f"[{rec['data']}]:{port}"
            if k not in seen: seen.add(k); results.append((k, rec["data"], port))
    return results

def probe_proxyip(ip, port, timeout_ms):
    out = {"ok":False,"connect_ms":-1,"tls_ms":-1,"http_ms":-1,
           "exit_ip":"","exit_colo":"","error":""}
    timeout_s = timeout_ms / 1000.0
    sock = ssock = None
    try:
        t0 = time.time()
        sock = socket.create_connection((ip, port), timeout=timeout_s)
        out["connect_ms"] = int((time.time()-t0)*1000)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        t0 = time.time()
        ssock = ctx.wrap_socket(sock, server_hostname=PROBE_HOST)
        out["tls_ms"] = int((time.time()-t0)*1000); sock = None
        t0 = time.time()
        req = (f"GET / HTTP/1.1\r\nHost: {PROBE_HOST}\r\n"
               f"Accept: application/json\r\nUser-Agent: Mozilla/5.0\r\n"
               f"Accept-Encoding: identity\r\nConnection: close\r\n\r\n")
        ssock.sendall(req.encode())
        resp = b""
        while len(resp) < 8192:
            try:
                c = ssock.recv(4096)
                if not c: break
                resp += c
            except: break
        out["http_ms"] = int((time.time()-t0)*1000)
        text = resp.decode("utf-8", errors="ignore")
        if not text: out["error"]="empty response"; return out
        si = text.find("\r\n\r\n")
        if si < 0: out["error"]="malformed"; return out
        header, body = text[:si], text[si+4:]
        if "transfer-encoding: chunked" in header.lower():
            dec = []; rem = body
            while rem:
                le = rem.find("\r\n")
                if le < 0: break
                try: cs = int(rem[:le].split(";")[0].strip(), 16)
                except ValueError: break
                if cs == 0: break
                dec.append(rem[le+2:le+2+cs]); rem = rem[le+2+cs+2:]
            body = "".join(dec)
        try: status = int(text.split(" ",2)[1])
        except: status = 0
        if status != 200: out["error"]=f"status {status}"; return out
        try: payload = json.loads(body)
        except: out["error"]="invalid json"; return out
        exit_ip = payload.get("ip") or payload.get("ipAddress") or ""
        if not exit_ip: out["error"]="missing exit ip"; return out
        out["ok"] = True
        out["exit_ip"] = exit_ip
        out["exit_colo"] = payload.get("colo","")
    except socket.timeout: out["error"]="timeout"
    except ConnectionRefusedError: out["error"]="refused"
    except ConnectionResetError: out["error"]="reset"
    except ssl.SSLError as e: out["error"]=f"tls: {getattr(e,'reason',str(e))}"
    except OSError as e: out["error"]=str(e)
    except Exception as e: out["error"]=f"{type(e).__name__}: {e}"
    finally:
        for s in (ssock, sock):
            if s:
                try: s.close()
                except: pass
    return out

def get_geo(ip):
    with _geo_lock:
        if ip in _geo_cache: return _geo_cache[ip]
    try:
        with urlopen(Request(GEO_API.format(ip=ip)), timeout=5) as r:
            d = json.loads(r.read())
            if d.get("status") == "success":
                res = {"country":d.get("countryCode",""),"city":d.get("city",""),
                       "isp":d.get("isp",""),"org":d.get("org","")}
                with _geo_lock: _geo_cache[ip] = res
                return res
    except: pass
    return {}

def check_target(target_tuple, timeout_ms):
    display, ip, port = target_tuple
    res = Result(input_addr="", resolved_target=display, ip=ip, port=port)
    geo = get_geo(ip)
    if geo:
        res.proxy_country = geo.get("country","")
        res.proxy_city = geo.get("city","")
        res.proxy_isp = geo.get("isp","")
    t = probe_proxyip(ip, port, timeout_ms)
    for k, v in t.items():
        if hasattr(res, k): setattr(res, k, v)
    if res.ok and res.exit_ip and not res.exit_org:
        eg = get_geo(res.exit_ip)
        if eg: res.exit_org = eg.get("org","")
    return res

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("ProxyIP Checker")
        self.root.geometry("1120x720")
        self.root.minsize(940, 560)
        s = ttk.Style()
        for t in ("vista","winnative","clam"):
            if t in s.theme_names(): s.theme_use(t); break
        s.configure("Treeview", rowheight=24, font=("Microsoft YaHei UI",9))
        s.configure("Treeview.Heading", font=("Microsoft YaHei UI",9,"bold"))
        for w in ("TLabel","TButton","TLabelframe.Label"):
            s.configure(w, font=("Microsoft YaHei UI",9))
        self.results = []; self.is_running = False; self._build()

    def _build(self):
        top = ttk.LabelFrame(self.root, text=" ProxyIP（每行一个） ", padding=8)
        top.pack(fill=tk.X, padx=10, pady=(10,4))
        row = ttk.Frame(top); row.pack(fill=tk.X)
        tf = ttk.Frame(row); tf.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.txt = tk.Text(tf, height=5, font=("Consolas",10), wrap=tk.NONE)
        sy = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.txt.yview)
        self.txt.configure(yscrollcommand=sy.set)
        self.txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); sy.pack(side=tk.RIGHT, fill=tk.Y)
        bf = ttk.Frame(row); bf.pack(side=tk.RIGHT, padx=(8,0))
        ttk.Button(bf, text="从文件导入", command=self._import, width=12).pack(pady=2)
        ttk.Button(bf, text="清空", command=lambda:self.txt.delete("1.0",tk.END), width=12).pack(pady=2)
        ttk.Button(bf, text="粘贴", command=self._paste, width=12).pack(pady=2)

        ctrl = ttk.Frame(self.root); ctrl.pack(fill=tk.X, padx=10, pady=4)
        lf = ttk.Frame(ctrl); lf.pack(side=tk.LEFT)
        ttk.Label(lf, text="默认端口:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="443")
        ttk.Combobox(lf, textvariable=self.port_var, values=[str(p) for p in CF_PORTS], width=6).pack(side=tk.LEFT, padx=(2,12))
        ttk.Label(lf, text="超时(ms):").pack(side=tk.LEFT)
        self.to_var = tk.StringVar(value="8000")
        ttk.Spinbox(lf, from_=2000, to=30000, increment=1000, width=6, textvariable=self.to_var).pack(side=tk.LEFT, padx=(2,12))
        ttk.Label(lf, text="并发:").pack(side=tk.LEFT)
        self.wk_var = tk.StringVar(value="30")
        ttk.Spinbox(lf, from_=1, to=200, width=4, textvariable=self.wk_var).pack(side=tk.LEFT)
        rf = ttk.Frame(ctrl); rf.pack(side=tk.RIGHT)
        self.start_btn = ttk.Button(rf, text="开始检测", command=self._start, width=10)
        self.start_btn.pack(side=tk.LEFT, padx=3)
        self.stop_btn = ttk.Button(rf, text="停止", command=self._stop, width=6, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=3)
        ttk.Button(rf, text="导出", command=self._export, width=6).pack(side=tk.LEFT, padx=3)
        ttk.Button(rf, text="复制可用", command=self._copy_alive, width=8).pack(side=tk.LEFT, padx=3)

        rf2 = ttk.LabelFrame(self.root, text=" 检测结果 ", padding=4)
        rf2.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4,4))
        cols = ("idx","input","target","port","status","exit_ip","colo",
                "location","isp","org","conn","tls","http","note")
        self.tree = ttk.Treeview(rf2, columns=cols, show="headings", selectmode="extended")
        hd = {"idx":("#",35,tk.CENTER),"input":("来源",140,tk.W),
              "target":("目标IP",115,tk.W),"port":("端口",42,tk.CENTER),
              "status":("状态",45,tk.CENTER),"exit_ip":("出站IP",115,tk.W),
              "colo":("CF节点",48,tk.CENTER),"location":("位置",90,tk.W),
              "isp":("ISP",100,tk.W),"org":("组织",110,tk.W),
              "conn":("TCP",42,tk.CENTER),"tls":("TLS",42,tk.CENTER),
              "http":("HTTP",45,tk.CENTER),"note":("备注",120,tk.W)}
        for c,(title,w,anchor) in hd.items():
            self.tree.heading(c, text=title)
            self.tree.column(c, width=w, anchor=anchor, stretch=(c in ("input","target","exit_ip","location","isp","org","note")))
        self.tree.tag_configure("ok", background="#E8F5E9")
        self.tree.tag_configure("fail", background="#FFEBEE")
        self.tree.tag_configure("dns_fail", background="#FFF3E0")
        sy2 = ttk.Scrollbar(rf2, orient=tk.VERTICAL, command=self.tree.yview)
        sx2 = ttk.Scrollbar(rf2, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=sy2.set, xscrollcommand=sx2.set)
        self.tree.grid(row=0,column=0,sticky="nsew"); sy2.grid(row=0,column=1,sticky="ns")
        sx2.grid(row=1,column=0,sticky="ew"); rf2.grid_rowconfigure(0,weight=1); rf2.grid_columnconfigure(0,weight=1)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="复制选中行", command=self._copy_sel)
        menu.add_command(label="复制可用地址", command=self._copy_alive)
        menu.add_separator(); menu.add_command(label="清空结果", command=self._clear)
        self.tree.bind("<Button-3>", lambda e:menu.tk_popup(e.x_root,e.y_root))
        sf = ttk.Frame(self.root); sf.pack(fill=tk.X, padx=10, pady=(0,8))
        self.prog = ttk.Progressbar(sf, mode="determinate"); self.prog.pack(fill=tk.X, pady=(0,3))
        self.st_var = tk.StringVar(value="就绪"); ttk.Label(sf, textvariable=self.st_var).pack(side=tk.LEFT)
        self.stat_var = tk.StringVar(); ttk.Label(sf, textvariable=self.stat_var).pack(side=tk.RIGHT)

    def _import(self):
        fp = filedialog.askopenfilename(filetypes=[("文本","*.txt *.csv"),("所有","*.*")])
        if fp:
            try:
                with open(fp,"r",encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
                if lines:
                    if self.txt.get("1.0",tk.END).strip(): self.txt.insert(tk.END,"\n")
                    self.txt.insert(tk.END, "\n".join(lines))
            except Exception as e: messagebox.showerror("错误", str(e))
    def _paste(self):
        try: self.txt.insert(tk.INSERT, self.root.clipboard_get())
        except tk.TclError: pass
    def _clear(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        self.results.clear(); self.stat_var.set(""); self.prog["value"]=0
    def _copy_sel(self):
        sel = self.tree.selection()
        if sel:
            lines = ["\t".join(str(v) for v in self.tree.item(i,"values")) for i in sel]
            self.root.clipboard_clear(); self.root.clipboard_append("\n".join(lines))
    def _copy_alive(self):
        alive = list(dict.fromkeys(r.resolved_target for r in self.results if r.ok))
        if not alive: messagebox.showinfo("提示","没有可用的ProxyIP"); return
        self.root.clipboard_clear(); self.root.clipboard_append("\n".join(alive))
        self.st_var.set(f"已复制 {len(alive)} 个可用地址")
    def _export(self):
        if not self.results: messagebox.showinfo("提示","没有结果"); return
        fp = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json"),("TXT","*.txt")])
        if not fp: return
        try:
            if fp.endswith(".json"):
                data = {"time":datetime.now().isoformat(),"total":len(self.results),
                        "alive":sum(1 for r in self.results if r.ok),
                        "results":[asdict(r) for r in self.results]}
                with open(fp,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False,indent=2)
            else:
                with open(fp,"w",encoding="utf-8") as f:
                    for r in self.results:
                        if r.ok: f.write(f"{r.resolved_target}\n")
            messagebox.showinfo("成功", f"已保存: {fp}")
        except Exception as e: messagebox.showerror("错误", str(e))

    def _start(self):
        text = self.txt.get("1.0",tk.END).strip()
        if not text: messagebox.showwarning("提示","请输入ProxyIP地址"); return
        addrs = list(dict.fromkeys(l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")))
        if not addrs: return
        try: timeout_ms = int(self.to_var.get())
        except: timeout_ms = 8000
        try: workers = int(self.wk_var.get())
        except: workers = 30
        self._clear(); self.is_running = True
        self.start_btn.configure(state=tk.DISABLED); self.stop_btn.configure(state=tk.NORMAL)
        self.st_var.set(f"正在解析 {len(addrs)} 个地址...")
        threading.Thread(target=self._run, args=(addrs,timeout_ms,workers), daemon=True).start()

    def _stop(self): self.is_running = False

    def _run(self, addrs, timeout_ms, workers):
        all_targets = []
        for addr in addrs:
            if not self.is_running: break
            self.root.after(0, lambda a=addr: self.st_var.set(f"解析中: {a}"))
            targets = handle_resolve(addr)
            if not targets:
                r = Result(input_addr=addr, error="未解析到可检测目标")
                self.results.append(r)
                self.root.after(0, self._add_dns_fail_row, addr)
            else:
                for display, ip, port in targets:
                    all_targets.append((addr, display, ip, port))
        if not self.is_running:
            self.root.after(0, self._done, 0, 0, 0); return
        total = len(all_targets)
        self.root.after(0, self._set_prog_max, total)
        self.root.after(0, lambda: self.st_var.set(f"解析完成，共 {total} 个目标，开始检测..."))
        done = ok_n = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, max(total,1))) as exe:
            fm = {}
            for i,(src,display,ip,port) in enumerate(all_targets):
                fm[exe.submit(check_target,(display,ip,port),timeout_ms)] = (i,src,display)
            for fut in concurrent.futures.as_completed(fm):
                if not self.is_running: exe.shutdown(wait=False,cancel_futures=True); break
                idx,src,display = fm[fut]
                try: r = fut.result()
                except Exception as e: r = Result(input_addr=src, resolved_target=display, error=str(e))
                r.input_addr = src; self.results.append(r); done += 1
                if r.ok: ok_n += 1
                self.root.after(0, self._add_row, done, r)
                self.root.after(0, self._upd, done, total, ok_n)
        self.root.after(0, self._done, done, total, ok_n)

    def _set_prog_max(self, total): self.prog["maximum"] = max(total,1)
    def _add_dns_fail_row(self, addr):
        self.tree.insert("",tk.END,tags=("dns_fail",),values=("-",addr,"","","DNS","","","","","","","","","未解析到可检测目标"))
    def _add_row(self, idx, r):
        st = "OK" if r.ok else "FAIL"
        loc = f"{r.proxy_country} {r.proxy_city}".strip()
        conn = str(r.connect_ms) if r.connect_ms>=0 else ""
        tls_t = str(r.tls_ms) if r.tls_ms>=0 else ""
        http_t = str(r.http_ms) if r.http_ms>=0 else ""
        tag = "ok" if r.ok else "fail"
        self.tree.insert("",tk.END,tags=(tag,),
            values=(idx,r.input_addr,r.ip,r.port,st,r.exit_ip,r.exit_colo,loc,r.proxy_isp,r.exit_org,conn,tls_t,http_t,r.error))
    def _upd(self, done, total, ok_n):
        self.prog["value"] = done; self.st_var.set(f"检测中 {done}/{total} ...")
        self.stat_var.set(f"OK: {ok_n} | FAIL: {done-ok_n}")
    def _done(self, done, total, ok_n):
        self.is_running = False; self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED); self.prog["value"] = done
        self.st_var.set(f"完成 - 共{done}个目标 | OK:{ok_n} | FAIL:{done-ok_n}")

def main():
    try:
        from ctypes import windll; windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    root = tk.Tk(); App(root); root.mainloop()

if __name__ == "__main__": main()
