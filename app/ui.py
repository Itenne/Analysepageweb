from __future__ import annotations
import queue, threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from concurrent.futures import ThreadPoolExecutor, as_completed
from .parsers import load_urls
from .http_client import WebTester
from .public_ip import detect_public_ip
from .exporters import export_csv, export_html
class ValidatorUI(ttk.Frame):
    def __init__(self, root, tester):
        super().__init__(root,padding=10); self.root,self.tester=root,tester; self.pack(fill="both",expand=True); self.urls=[]; self.results=[]; self.public_ip={}; self.cancel=threading.Event(); self.events=queue.Queue(); self._build(); self.root.after(100,self._poll)
    def _build(self):
        self.root.title("SASE Web Filtering Validation Tool"); ttk.Label(self,text="SASE Web Filtering Validation Tool",font=("Segoe UI",16,"bold")).pack(anchor="w")
        self.ip_label=ttk.Label(self,text="Public Internet IP: not detected"); self.ip_label.pack(anchor="w",pady=(2,8))
        bar=ttk.Frame(self); bar.pack(fill="x");
        for text,cmd in [("Load URLs",self.load),("Add URL",self.add),("Detect Public IP",self.detect_ip),("Test All",self.test_all),("Stop",self.stop),("Export CSV",self.export_csv),("Export HTML",self.export_html),("Clear",self.clear)]: ttk.Button(bar,text=text,command=cmd).pack(side="left",padx=2)
        cols=("url","status","http","final","ip","duration","classification","confidence"); self.tree=ttk.Treeview(self,columns=cols,show="headings",height=14)
        for col,title,width in zip(cols,["URL","Status","HTTP","Final URL","Public IP","Duration","Classification","Confidence"],[260,90,60,260,120,80,140,90]): self.tree.heading(col,text=title); self.tree.column(col,width=width,stretch=col in {"url","final"})
        self.tree.pack(fill="both",expand=True); self.tree.bind("<<TreeviewSelect>>",self.detail); self.progress=ttk.Progressbar(self,mode="determinate"); self.progress.pack(fill="x",pady=5); self.details=tk.Text(self,height=10,wrap="word"); self.details.pack(fill="x")
    def load(self):
        path=filedialog.askopenfilename(filetypes=[("URL files","*.txt *.csv")]);
        if path:
            try: self.urls.extend(x["url"] for x in load_urls(path)); self.refresh_pending()
            except Exception as e: messagebox.showerror("Load URLs",str(e))
    def add(self):
        value=simpledialog.askstring("Add URL","HTTP(S) URL:");
        if value:
            try: self.urls.extend(x["url"] for x in load_urls(self._temporary(value))); self.refresh_pending()
            except Exception as e: messagebox.showerror("Add URL",str(e))
    def _temporary(self,v):
        from pathlib import Path
        path=Path.home()/".sase_validator_single_url.txt"; path.write_text(v); return path
    def refresh_pending(self):
        self.tree.delete(*self.tree.get_children()); [self.tree.insert("","end",values=(url,"PENDING","","","","","","")) for url in self.urls]
    def detect_ip(self): threading.Thread(target=lambda:self.events.put(("ip",detect_public_ip(use_system_proxy=self.tester.session.trust_env))),daemon=True).start()
    def test_all(self):
        self.cancel.clear(); self.results=[]; self.progress.configure(maximum=len(self.urls),value=0); threading.Thread(target=self._run,daemon=True).start()
    def _run(self):
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures={pool.submit(self.tester.test,url,self.public_ip.get("ip","")):url for url in self.urls}
            for future in as_completed(futures):
                if self.cancel.is_set(): break
                try:self.events.put(("result",future.result()))
                except Exception as exc:self.events.put(("error",str(exc)))
        self.events.put(("done",None))
    def stop(self): self.cancel.set()
    def _poll(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=="ip": self.public_ip=value; self.ip_label.config(text=f"Public Internet IP: {value['ip'] or 'not detected'} (confidence: {value['confidence']})")
                elif kind=="result": self.results.append(value); self.tree.insert("","end",values=(value.url,"OK" if value.classification=="ACCESS_ALLOWED" else "BLOCKED" if value.classification in {"ACCESS_DENIED","IP_RESTRICTION"} else "ERROR",value.http_status or "",value.final_url,value.public_ip,value.duration_ms or "",value.classification,value.confidence)); self.progress.step(1)
                elif kind=="error": messagebox.showerror("Test",value)
        except queue.Empty: pass
        self.root.after(100,self._poll)
    def detail(self,_=None):
        selected=self.tree.selection()
        if not selected:return
        url=self.tree.item(selected[0],"values")[0]; r=next((x for x in self.results if x.url==url),None)
        if r: self.details.delete("1.0","end"); self.details.insert("end",f"URL: {r.url}\nFinal URL: {r.final_url}\nDNS: {r.dns.status} {', '.join(r.dns.addresses)}\nHTTP: {r.http_status}\nClassification: {r.classification} ({r.confidence})\nReason: {r.reason}\nIndicators: {', '.join(r.indicators)}\nError: {r.error}")
    def export_csv(self):
        path=filedialog.asksaveasfilename(defaultextension=".csv"); path and export_csv(self.results,path)
    def export_html(self):
        path=filedialog.asksaveasfilename(defaultextension=".html"); path and export_html(self.results,path,self.public_ip)
    def clear(self): self.urls=[]; self.results=[]; self.refresh_pending(); self.details.delete("1.0","end")
