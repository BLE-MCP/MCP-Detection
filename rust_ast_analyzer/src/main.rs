use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use indexmap::IndexMap;
use lazy_static::lazy_static;
use quote::quote;
use serde::Serialize;
use serde_json::{json, Value};
use syn::{
    punctuated::Punctuated, spanned::Spanned, token::Comma, visit::Visit, Expr, ExprLit, ItemFn,
    Lit, Pat, Stmt,
};
use walkdir::WalkDir;


#[derive(Debug, Clone)]
struct VariableInfo {
    source: String,
    trace: Vec<String>,
    value: Option<String>,
}

#[derive(Debug, Serialize)]
struct CallInfo {
    api: String,
    location: Location,
    arguments: IndexMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    produced_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct Location {
    file: String,
    line: usize,
    function: String,
}

#[derive(Debug, Serialize)]
struct FileOutput {
    file: String,
    calls: Vec<CallInfo>,
}

#[derive(Debug, Serialize)]
struct Dependency {
    from: String,
    to: String,
    #[serde(rename = "type")]
    ty: String,
    resource: String,
}

#[derive(Debug, Serialize)]
struct Output {
    project: String,
    language: String,
    files: Vec<FileOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cross_file_dependencies: Vec<Dependency>,
}


#[derive(Debug)]
struct AnalysisVisitor {
    file_path: String,
    current_fn: String,
    calls: Vec<CallInfo>,
    vars: HashMap<String, VariableInfo>,

    produced_files: HashMap<String, String>,
    consumed_files: HashMap<String, String>,
    produced_events: HashMap<String, String>,
    consumed_events: HashMap<String, String>,
}

impl AnalysisVisitor {
    fn handle_call(&mut self, func_name: &str, args: &Punctuated<Expr, Comma>, line_no: usize) {
        let mut args_json: IndexMap<String, Value> = IndexMap::new();
        for arg in args {
            let arg_code = quote! {#arg}.to_string();
            let mut map = serde_json::Map::new();

            if let Some(info) = self.vars.get(&arg_code) {
                match info.source.as_str() {
                    "literal" => {
                        map.insert("type".into(), "constant".into());
                        map.insert(
                            "value".into(),
                            info.value.clone().unwrap_or_default().into(),
                        );
                    }
                    _ => {
                        map.insert("type".into(), "function_return".into());
                        map.insert("value".into(), info.source.clone().into());
                        map.insert("produced_as".into(), arg_code.clone().into());
                        map.insert("_trace".into(), json!(info.trace.clone()));
                    }
                }
            } else {
                map.insert("type".into(), "unknown".into());
                map.insert("value".into(), arg_code.clone().into());
            }
            args_json.insert(arg_code, Value::Object(map));
        }

        let mut produced_as = None;
        let first_arg_code = args
            .first()
            .map(|e| quote! {#e}.to_string())
            .unwrap_or_default();

        if IO_WRITE_APIS.contains(func_name) {
            let handle = format!("IO#{first_arg_code}");
            self.produced_files
                .insert(first_arg_code.clone(), func_name.into());
            produced_as = Some(handle);
        } else if IO_READ_APIS.contains(func_name) {
            let handle = format!("IO#{first_arg_code}");
            self.consumed_files
                .insert(first_arg_code.clone(), func_name.into());
            let mut obj = serde_json::Map::new();
            obj.insert("type".into(), "function_return".into());
            obj.insert("value".into(), handle.clone().into());
            args_json.insert("path".into(), Value::Object(obj));
        }

        if EVT_PUB_APIS.contains(func_name) {
            let handle = format!("EVT#{first_arg_code}");
            self.produced_events
                .insert(first_arg_code.clone(), func_name.into());
            produced_as = Some(handle);
        } else if EVT_SUB_APIS.contains(func_name) {
            let handle = format!("EVT#{first_arg_code}");
            self.consumed_events
                .insert(first_arg_code.clone(), func_name.into());
            let mut obj = serde_json::Map::new();
            obj.insert("type".into(), "function_return".into());
            obj.insert("value".into(), handle.clone().into());
            args_json.insert("topic".into(), Value::Object(obj));
        }

        let trace = produced_as
            .as_ref()
            .and_then(|h| self.vars.get(h).map(|v| v.trace.clone()))
            .or_else(|| Some(vec![func_name.to_string()]));

        self.calls.push(CallInfo {
            api: func_name.into(),
            location: Location {
                file: self.file_path.clone(),
                line: line_no,
                function: self.current_fn.clone(),
            },
            arguments: args_json,
            produced_as,
            trace,
        });
    }
}

impl<'ast> Visit<'ast> for AnalysisVisitor {
    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        self.current_fn = i.sig.ident.to_string();
        syn::visit::visit_item_fn(self, i);
    }

    fn visit_stmt(&mut self, s: &'ast Stmt) {
        if let Stmt::Local(local) = s {
            if let Some(init) = &local.init {
                let var_name = match &local.pat {
                    Pat::Ident(p) => p.ident.to_string(),
                    _ => "unknown".into(),
                };
                match &*init.expr {
                    Expr::Lit(ExprLit { lit: Lit::Str(ls), .. }) => {
                        self.vars.insert(
                            var_name,
                            VariableInfo {
                                source: "literal".into(),
                                trace: vec![],
                                value: Some(ls.value()),
                            },
                        );
                    }
                    Expr::Path(p) => {
                        let func = p.path.segments.last().unwrap().ident.to_string();
                        self.vars.insert(
                            var_name,
                            VariableInfo {
                                source: func.clone(),
                                trace: vec![func],
                                value: None,
                            },
                        );
                    }
                    _ => {}
                }
            }
        }

        match s {
            Stmt::Expr(Expr::Call(call), _) => {
                if let Expr::Path(p) = &*call.func {
                    let func_name = p.path.segments.last().unwrap().ident.to_string();
                    let ln = call.span().start().line;
                    self.handle_call(&func_name, &call.args, ln);
                }
            }
            Stmt::Expr(Expr::MethodCall(mc), _) => {
                let func_name = mc.method.to_string();
                let ln = mc.method.span().start().line;
                let mut all_args: Punctuated<Expr, Comma> = Punctuated::new();
                all_args.push((*mc.receiver.clone()).clone());
                for a in &mc.args {
                    all_args.push(a.clone());
                }
                self.handle_call(&func_name, &all_args, ln);
            }
            _ => {}
        }
        syn::visit::visit_stmt(self, s);
    }
}

/* ──────── File & YAML Tools ──────── */

fn collect_rs_files(dir: &Path) -> Vec<PathBuf> {
    let skip: HashSet<&str> = [
        ".git", "target", ".cargo", ".idea", ".vscode", "node_modules",
    ]
    .iter()
    .copied()
    .collect();

    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                return !skip.contains(name.as_str()) && !name.starts_with('.');
            }
            true
        })
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .map(|s| s == "rs")
                    .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn extract_pipeline_ir(project_dir: &Path) -> Vec<FileOutput> {
    use serde_yaml::Value as YamlVal;
    let yaml_path = ["pipeline.yml", "pipeline.yaml"]
        .iter()
        .map(|f| project_dir.join(f))
        .find(|p| p.exists());
    let Some(yaml_path) = yaml_path else { return vec![] };

    let doc: YamlVal = match fs::read_to_string(&yaml_path)
        .ok()
        .and_then(|s| serde_yaml::from_str(&s).ok())
    {
        Some(d) => d,
        None => return vec![],
    };

    let stages: Vec<String> = if let Some(seq) = doc.get("pipeline").and_then(|v| v.as_sequence())
    {
        seq.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    } else if let Some(seq) = doc.as_sequence() {
        seq.iter()
            .map(|v| {
                if let Some(s) = v.as_str() {
                    s.to_string()
                } else {
                    serde_json::to_string(v).unwrap_or_else(|_| "<unknown>".to_string())
                }
            })
            .collect()
    } else {
        vec![]
    };
    if stages.is_empty() {
        return vec![];
    }

    let mut calls = Vec::<CallInfo>::new();
    for (idx, stg) in stages.iter().enumerate() {
        let mut args = IndexMap::new();
        if idx > 0 {
            args.insert(
                "in".into(),
                json!({"type":"function_return","value":format!("PIPE#{}", stages[idx-1]),"_trace":[]}),
            );
        }
        calls.push(CallInfo {
            api: stg.clone(),
            location: Location {
                file: format!(
                    "__pipeline__/{}",
                    yaml_path.file_name().unwrap().to_string_lossy()
                ),
                line: idx + 1,
                function: "pipeline".into(),
            },
            arguments: args,
            produced_as: Some(format!("PIPE#{}", stg)),
            trace: Some(vec![stg.clone()]),
        });
    }

    vec![FileOutput {
        file: "__pipeline__".into(),
        calls,
    }]
}


lazy_static! {
    static ref IO_WRITE_APIS: HashSet<&'static str> =
        ["write", "write_all", "create", "set_len", "writeln"]
            .iter()
            .copied()
            .collect();

    static ref IO_READ_APIS: HashSet<&'static str> =
        ["read", "read_to_end", "read_to_string", "open"]
            .iter()
            .copied()
            .collect();

    static ref EVT_PUB_APIS: HashSet<&'static str> =
        ["publish", "emit", "send"].iter().copied().collect();

    static ref EVT_SUB_APIS: HashSet<&'static str> =
        ["subscribe", "on", "recv", "receive"].iter().copied().collect();
}


fn col_to_a1(col: u32) -> String {
    let mut c = col;
    let mut s = String::new();
    while c > 0 {
        let rem = (c - 1) % 26;
        s.insert(0, (b'A' + rem as u8) as char);
        c = (c - 1) / 26;
    }
    s
}
fn a1(col: u32, row: u32) -> String {
    format!("{}{}", col_to_a1(col), row)
}

fn fmt_hms_ms(d: Duration) -> String {
    let total_ms = d.as_millis() as u64;
    let hh = total_ms / 3_600_000;
    let mm = (total_ms % 3_600_000) / 60_000;
    let ss = (total_ms % 60_000) / 1000;
    let ms = total_ms % 1000;
    format!("{:02}:{:02}:{:02}.{:03}", hh, mm, ss, ms)
}

fn append_excel_per_project(
    xlsx_path: &Path,
    project: &str,
    elapsed: Duration,
) -> Result<(), String> {
    let sheet_name = "PerProject";
    let ms = elapsed.as_secs_f64() * 1000.0;
    let sec = elapsed.as_secs_f64();
    let hms = fmt_hms_ms(elapsed);

    let mut book = if xlsx_path.exists() {
        umya_spreadsheet::reader::xlsx::read(xlsx_path).map_err(|e| format!("read xlsx: {e}"))?
    } else {
        umya_spreadsheet::new_file()
    };

    if book.get_sheet_by_name_mut(sheet_name).is_none() {
        let _ = book.new_sheet(sheet_name);
        if let Some(ws) = book.get_sheet_by_name_mut(sheet_name) {
            ws.get_cell_mut(a1(1, 1).as_str()).set_value("Index");
            ws.get_cell_mut(a1(2, 1).as_str()).set_value("Project");
            ws.get_cell_mut(a1(3, 1).as_str()).set_value("Elapsed (ms)");
            ws.get_cell_mut(a1(4, 1).as_str()).set_value("Elapsed (seconds)");
            ws.get_cell_mut(a1(5, 1).as_str()).set_value("Elapsed (hh:mm:ss.fff)");

        }
    }

    let ws = book
        .get_sheet_by_name_mut(sheet_name)
        .ok_or_else(|| "missing sheet".to_string())?;

    let last_row = ws.get_highest_row().max(1);
    let next_row = last_row + 1;
    let next_index = (next_row - 1) as i32;

    ws.get_cell_mut(a1(1, next_row).as_str()).set_value(next_index.to_string());
    ws.get_cell_mut(a1(2, next_row).as_str()).set_value(project);
    ws.get_cell_mut(a1(3, next_row).as_str()).set_value(format!("{:.3}", ms));
    ws.get_cell_mut(a1(4, next_row).as_str()).set_value(format!("{:.3}", sec));
    ws.get_cell_mut(a1(5, next_row).as_str()).set_value(hms);

    umya_spreadsheet::writer::xlsx::write(&book, xlsx_path)
        .map_err(|e| format!("write xlsx: {e}"))?;
    Ok(())
}


fn find_rust_roots_second_level(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(level1) = fs::read_dir(root) {
        for l1 in level1.flatten() {
            let p1 = l1.path();
            if !p1.is_dir() {
                continue;
            }
            if let Ok(level2) = fs::read_dir(&p1) {
                for l2 in level2.flatten() {
                    let p2 = l2.path();
                    if p2.is_dir() {
                        if let Some(name) = p2.file_name().and_then(|s| s.to_str()) {
                            if name.eq_ignore_ascii_case("Rust") {
                                out.push(p2);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn contains_rs(dir: &Path) -> bool {
    !collect_rs_files(dir).is_empty()
}

fn find_projects_under_rust_root(rust_root: &Path) -> Vec<PathBuf> {
    let mut projects = Vec::new();
    if let Ok(ents) = fs::read_dir(rust_root) {
        for e in ents.flatten() {
            let p = e.path();
            if p.is_dir() && contains_rs(&p) {
                projects.push(p);
            }
        }
    }
    if projects.is_empty() && contains_rs(rust_root) {
        projects.push(rust_root.to_path_buf());
    }
    projects
}

fn safe_rel(root: &Path, p: &Path) -> String {
    pathdiff::diff_paths(p, root)
        .unwrap_or_else(|| p.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

fn safe_file_name(s: &str) -> String {
    s.replace('\\', "_")
        .replace('/', "_")
        .replace(':', "_")
        .replace('*', "_")
        .replace('?', "_")
        .replace('"', "_")
        .replace('<', "_")
        .replace('>', "_")
        .replace('|', "_")
}


fn fmt_hms_ms_for_print(d: Duration) -> String {
    fmt_hms_ms(d)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: cargo run --release -- <ROOT_DIR> <OUT_DIR or run_times.xlsx>");
        std::process::exit(1);
    }
    let root_dir = Path::new(&args[1]);
    let out_arg = Path::new(&args[2]);

    if !root_dir.is_dir() {
        eprintln!("❌ Directory does not exist：{}", root_dir.display());
        std::process::exit(1);
    }

    let (json_out_dir, excel_path) = if out_arg
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("xlsx"))
        .unwrap_or(false)
    {
        let json_dir = out_arg
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        (json_dir, out_arg.to_path_buf())
    } else {
        (out_arg.to_path_buf(), out_arg.join("run_times.xlsx"))
    };
    fs::create_dir_all(&json_out_dir).expect("Failed to create output directory");

    let rust_roots = find_rust_roots_second_level(root_dir);
    if rust_roots.is_empty() {
        println!("⚠️ No sub-folder named Rust was found in the given directory.");
        return;
    }

    let mut projects: Vec<PathBuf> = Vec::new();
    for rr in &rust_roots {
        projects.extend(find_projects_under_rust_root(rr));
    }
    if projects.is_empty() {
        println!("⚠️ No Rust projects were detected.");
        return;
    }

    let total = projects.len();
    let t_all0 = Instant::now();

    for (i, proj) in projects.iter().enumerate() {
        let rel = safe_rel(root_dir, proj);
        println!("\n📁 [{}/{}] Project: {}", i + 1, total, rel);
        let t0 = Instant::now();

        let rs_files = collect_rs_files(proj);
        let mut files_vec = Vec::<FileOutput>::new();
        let mut prod_files = HashMap::<String, String>::new();
        let mut cons_files = HashMap::<String, String>::new();
        let mut prod_evt = HashMap::<String, String>::new();
        let mut cons_evt = HashMap::<String, String>::new();

        for fp in rs_files {
            let code = fs::read_to_string(&fp).unwrap_or_default();
            let ast = match syn::parse_file(&code) {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("Parsing failed: {}", fp.display());
                    continue;
                }
            };

            let path_str = fp.to_string_lossy().to_string();
            let mut v = AnalysisVisitor {
                file_path: path_str.clone(),
                current_fn: "global".into(),
                calls: vec![],
                vars: HashMap::new(),
                produced_files: HashMap::new(),
                consumed_files: HashMap::new(),
                produced_events: HashMap::new(),
                consumed_events: HashMap::new(),
            };
            v.visit_file(&ast);

            prod_files.extend(v.produced_files);
            cons_files.extend(v.consumed_files);
            prod_evt.extend(v.produced_events);
            cons_evt.extend(v.consumed_events);

            files_vec.push(FileOutput {
                file: path_str,
                calls: v.calls,
            });
        }

        files_vec.extend(extract_pipeline_ir(proj));

        let mut deps = Vec::<Dependency>::new();
        for (res, c) in &cons_files {
            if let Some(p) = prod_files.get(res) {
                deps.push(Dependency {
                    from: p.clone(),
                    to: c.clone(),
                    ty: "file_io".into(),
                    resource: res.clone(),
                });
            }
        }
        for (topic, c) in &cons_evt {
            if let Some(p) = prod_evt.get(topic) {
                deps.push(Dependency {
                    from: p.clone(),
                    to: c.clone(),
                    ty: "event".into(),
                    resource: topic.clone(),
                });
            }
        }

        let output = Output {
            project: rel.clone(),
            language: "rust".into(),
            files: files_vec,
            cross_file_dependencies: deps,
        };

        let out_path = json_out_dir.join(format!("{}.json", safe_file_name(&rel)));
        let mut f = File::create(&out_path).expect("Failed to write file");
        writeln!(f, "{}", serde_json::to_string_pretty(&output).unwrap()).unwrap();
        println!("✅  Output → {}", out_path.display());

        let elapsed = t0.elapsed();
        if let Err(e) = append_excel_per_project(&excel_path, &format!("rs/{}", rel), elapsed) {
            eprintln!("Failed to write file Excel: {}", e);
        }

        let sofar = t_all0.elapsed();
        let avg = sofar / (i as u32 + 1);
        let remain = total - (i + 1);
        let eta = avg * (remain as u32);
        println!(
            "⏱️  Elapsed {}  |  ETA {}",
            fmt_hms_ms_for_print(elapsed),
            fmt_hms_ms_for_print(eta)
        );
    }

    println!(
        "\n🎉 Completed all {} projects; total time:{}",
        projects.len(),
        fmt_hms_ms_for_print(t_all0.elapsed())
    );
}
