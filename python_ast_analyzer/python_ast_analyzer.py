import os
import ast
import json
import base64
import argparse

LANGUAGE = "python"

IO_WRITE_APIS = {
    "open().write", "pathlib.Path.write_text", "pathlib.Path.write_bytes",
    "file.write", "json.dump", "yaml.dump", "pickle.dump", "csv.writer.writerow"
}

IO_READ_APIS = {
    "open().read", "pathlib.Path.read_text", "pathlib.Path.read_bytes",
    "file.read", "file.readlines", "json.load", "yaml.load", "pickle.load"
}

EVT_PUB_APIS = {
    "bus.emit", "bus.publish", "event_bus.emit", "kafka.producer.send", "socketio.emit"
}

EVT_SUB_APIS = {
    "bus.on", "bus.subscribe", "event_bus.on", "kafka.consumer.poll", "socketio.on"
}
# ───────────────────────── UTILITIES ─────────────────────────
def is_literal(node): return isinstance(node, ast.Constant)

def get_literal_value(node):
    if not isinstance(node, ast.Constant): return None
    val = node.value
    if val is Ellipsis: return "..."
    if isinstance(val, bytes):
        return {"type": "bytes", "base64": base64.b64encode(val).decode("ascii")}
    if isinstance(val, str):
        return f'"{val}"'
    if isinstance(val, complex): 
        return str(val)
    return val

def safe_unparse(node):
    try: return ast.unparse(node) if node else "null"
    except Exception: return "unknown"

def analyze_rhs_literal(node):
    if is_literal(node):
        return {"type": "constant", "value": get_literal_value(node)}
    if isinstance(node, ast.List):
        return {"type": "list_literal",
                "value": [analyze_rhs_literal(e) for e in node.elts]}
    if isinstance(node, ast.Dict):
        d = {}
        for k, v in zip(node.keys, node.values):
            key = str(get_literal_value(k)) if is_literal(k) else safe_unparse(k)
            d[key] = analyze_rhs_literal(v)
        return {"type": "dict_literal", "value": d}
    return None

def get_attribute_chain(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node = node.value
    if isinstance(node, ast.Name): parts.append(node.id)
    parts.reverse()
    return ".".join(parts)

def get_func_name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return get_attribute_chain(node)
    return safe_unparse(node)

def annotate_parents(tree):
    for n in ast.walk(tree):
        for ch in ast.iter_child_nodes(n):
            ch.parent = n

# ───────────────────────── AST ─────────────────────────
class CallExtractor(ast.NodeVisitor):
    def __init__(self, filepath):
        self.filepath = filepath.replace("/", "\\")
        self.calls = []
        self.cur_fn = None
        self.sym_stack = [{}]

    def cur_scope(self): return self.sym_stack[-1]

    def visit_FunctionDef(self, node):
        prev = self.cur_fn; self.cur_fn = node.name
        self.sym_stack.append({})
        self.generic_visit(node)
        self.sym_stack.pop(); self.cur_fn = prev
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var = node.targets[0].id; rhs = node.value
            if isinstance(rhs, ast.Call):
                fname = get_func_name(rhs.func)
                self.cur_scope()[var] = {
                    "type": "function_return", "value": fname,
                    "produced_as": var, "_trace": [fname]
                }
            elif (info := analyze_rhs_literal(rhs)): self.cur_scope()[var] = info
        self.generic_visit(node)

    def visit_Call(self, node):
        fname = get_func_name(node.func)
        args = {}
        for i, a in enumerate(node.args):
            args[f"arg{i+1}"] = self._analyze_arg(a)
        for kw in node.keywords:
            if kw.arg: args[kw.arg] = self._analyze_arg(kw.value)

        call = {
            "api": fname,
            "location": {
                "file": self.filepath, "line": node.lineno,
                "function": self.cur_fn or "global"
            },
            "arguments": args,
            "trace": [fname]
        }

        key = None
        if node.args:
            if is_literal(node.args[0]):
               lit = get_literal_value(node.args[0])
               key = (lit.strip('"') if isinstance(lit, str) else str(lit))
            else:
                key = safe_unparse(node.args[0])

        if fname in IO_WRITE_APIS and key:
            call["produced_as"] = f"IO#{key}"
        if fname in IO_READ_APIS and key:
            args["path"] = {"type": "function_return", "value": f"IO#{key}"}
        if fname in EVT_PUB_APIS and key:
            call["produced_as"] = f"EVT#{key}"
        if fname in EVT_SUB_APIS and key:
            args["topic"] = {"type": "function_return", "value": f"EVT#{key}"}

        parent = getattr(node, "parent", None)
        if isinstance(parent, ast.Assign) and isinstance(parent.targets[0], ast.Name):
            call["produced_as"] = parent.targets[0].id

        self.calls.append(call)
        self.generic_visit(node)

    # ---------- helper ----------
    def _analyze_arg(self, n):
        if is_literal(n): return {"type":"constant","value":get_literal_value(n)}
        if isinstance(n,(ast.List,ast.Dict)): return analyze_rhs_literal(n)
        if isinstance(n, ast.Name):
            if (info:=self._resolve(n.id)): return info
            return {"type":"variable","value":n.id}
        if isinstance(n, ast.Call):
            fn = get_func_name(n.func)
            return {"type":"function_return","value":fn,"_trace":[fn]}
        return {"type":"unknown","value":get_func_name(n)}

    def _resolve(self, name):
        for scope in reversed(self.sym_stack):
            if name in scope: return dict(scope[name])
        return None

def extract_calls_from_file(fp):
    try:
        src = open(fp, "r", encoding="utf-8").read()
        tree = ast.parse(src, filename=fp); annotate_parents(tree)
        ext = CallExtractor(fp); ext.visit(tree)
        return ext.calls
    except SyntaxError:
        print(f"⚠️  SyntaxError in {fp}, skipped."); return []
    except Exception as e:
        print(f"⚠️  Error parsing {fp}: {e}"); return []

def walk_project(path):
    out=[]
    for r,_,fs in os.walk(path):
        for f in fs:
            if f.endswith(".py") and not f.endswith("_test.py"):
                fp = os.path.join(r,f)
                calls = extract_calls_from_file(fp)
                if calls: out.append({"file":fp.replace("/","\\"),"calls":calls})
    return out

# ───────────────────────── YAML pipeline ─────────────────────────
def parse_pipeline_yaml(project_path):
    try:
        import yaml
    except ImportError:
        return []
    yml_path=None
    for n in ("pipeline.yaml","pipeline.yml"):
        p=os.path.join(project_path,n)
        if os.path.exists(p): yml_path=p; break
    if not yml_path: return []
    with open(yml_path,"r",encoding="utf-8") as f:
        doc=yaml.safe_load(f)
    stages=[]
    if isinstance(doc,list): stages=[str(s) for s in doc]
    elif isinstance(doc,dict) and isinstance(doc.get("pipeline"),list):
        stages=[str(s) for s in doc["pipeline"]]
    if not stages: return []
    calls=[]
    for i,stg in enumerate(stages):
        call={"api":stg,
              "location":{"file":"__pipeline__/"+os.path.basename(yml_path),
                          "line":i+1,"function":"pipeline"},
              "arguments":{},
              "trace":[stg],
              "produced_as":f"PIPE#{stg}"}
        if i>0:
            call["arguments"]["in"]={"type":"function_return","value":f"PIPE#{stages[i-1]}"}
        calls.append(call)
    return [{"file":"__pipeline__","calls":calls}]

# ───────────────────────── Project batch processing ─────────────────────────
def process_all_projects(root, out_dir):
    os.makedirs(out_dir,exist_ok=True)
    for name in os.listdir(root):
        proj=os.path.join(root,name)
        if not os.path.isdir(proj): continue
        print(f"📦 Processing {name}")
        files_ir = walk_project(proj)
        files_ir += parse_pipeline_yaml(proj)
        result={"project":name,"language":LANGUAGE,"files":files_ir}
        out_fp=os.path.join(out_dir,f"{name}.json")
        with open(out_fp, "w", encoding="utf-8", errors="surrogatepass") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        print(f"✅ Saved → {out_fp}")

# ───────────────────────── CLI ─────────────────────────
if __name__=="__main__":
    ap=argparse.ArgumentParser(description="Batch MCP IR Extractor (Python)")
    ap.add_argument("projects_dir"); ap.add_argument("output_dir")
    args=ap.parse_args()
    print(f"🗂️ Scanning: {args.projects_dir}")
    process_all_projects(args.projects_dir,args.output_dir)
    print("🎉 All projects processed!")

