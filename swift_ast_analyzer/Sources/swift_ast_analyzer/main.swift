import Foundation
import SwiftSyntax
import SwiftParser
import Yams

let IO_WRITE_APIS: Set<String> = [
    "FileHandle.write", "Data.write", "String.write",
    "FileManager.default.createFile", "ByteBuffer.writeString", "FileIO.write",
    "fs.writeFile", "fs.writeFileSync", "fs.appendFile", "fs.createWriteStream",
    "file_put_contents", "print", "NSLog", "os_log",
    "console.log", "winston.log", "pino.info", "bunyan.info"
]
let IO_READ_APIS: Set<String> = [
    "String(contentsOfFile:)", "Data(contentsOf:)", "FileHandle.readData",
    "FileIO.read",
    "fs.readFile", "fs.readFileSync", "fs.createReadStream",
    "file_get_contents",
    "JSON.parse", "PropertyListSerialization.propertyList",
    "YAMLDecoder.decode",
    "require", "import"
]
let EVT_PUB_APIS: Set<String> = [
    "NotificationCenter.default.post", "Subject.send", "PublishRelay.accept",
    "AsyncStream.yield", "bus.emit", "eventEmitter.emit", "publish",
    "window.dispatchEvent", "self.postMessage", "socket.send", "ws.send",
    "redisClient.publish", "kafkaProducer.send", "mqttClient.publish"
]
let EVT_SUB_APIS: Set<String> = [
    "NotificationCenter.default.addObserver", "Publisher.sink", "Observable.subscribe",
    "for await", "bus.on", "eventEmitter.on", "eventEmitter.addListener",
    "subscribe", "addEventListener", "socket.on", "ws.on",
    "redisClient.subscribe", "kafkaConsumer.on", "mqttClient.on"
]

fileprivate func j(_ s: String) -> String { String(data: try! JSONEncoder().encode(s), encoding: .utf8)! }
struct Argument { let type: String; let value: String; let producedAs: String?; let trace: [String]? }
struct Call { let api: String; let location: Location; var arguments: [Argument]; let producedAs: String?; let trace: [String]? }
struct Location { let file: String; let line: Int; let function: String }
struct FileIR   { let file: String;  let calls: [Call] }
struct OutputRoot { let project: String; let language = "swift"; let files: [FileIR] }

struct JSONWriter {
    private var lines: [String] = []; private let indent = "  "
    mutating func write(_ root: OutputRoot) {
        add("{",0)
        kv("project",j(root.project),1,true)
        kv("language",j(root.language),1,true)
        add("\"\("files")\" : [",1)
        for (iF,f) in root.files.enumerated() {
            add("{",2)
            kv("file",j(f.file),3,true)
            add("\"\("calls")\" : [",3)
            for (iC,c) in f.calls.enumerated() {
                add("{",4)
                kv("api",j(c.api),5,true)
                add("\"\("location")\" : {",5)
                kv("file",j(c.location.file),6,true)
                kv("line","\(c.location.line)",6,true)
                kv("function",j(c.location.function),6,false)
                add("}",5,true)
                add("\"\("arguments")\" : {",5)
                for (idxA,a) in c.arguments.enumerated() {
                    let k = "arg\(idxA+1)"
                    add("\"\(k)\" : {",6)
                    kv("type",j(a.type),7,true)
                    kv("value",j(a.value),7,a.producedAs != nil || a.trace != nil)
                    if let p=a.producedAs { kv("produced_as",j(p),7,a.trace != nil) }
                    if let tr=a.trace { add("\"\("_trace")\" : [ "+tr.map(j).joined(separator:", ")+" ]",7,false) }
                    add("}",6,idxA != c.arguments.count-1)
                }
                add("}",5,c.trace != nil || c.producedAs != nil)
                if let tr=c.trace { kv("trace","[ "+tr.map(j).joined(separator:", ")+" ]",5,c.producedAs != nil) }
                if let p=c.producedAs { kv("produced_as",j(p),5,false) }
                add("}",4,iC != f.calls.count-1)
            }
            add("]",3,false); add("}",2,iF != root.files.count-1)
        }
        add("]",1,false); add("}",0,false)
    }
    private mutating func add(_ s:String,_ lvl:Int,_ comma:Bool=false){ lines.append(String(repeating:indent,count:lvl)+s+(comma ? ",":"")) }
    private mutating func kv(_ k:String,_ v:String,_ lvl:Int,_ comma:Bool){ add("\"\(k)\" : \(v)"+(comma ? ",":""),lvl) }
    func build()->String{ lines.joined(separator:"\n") }
}

// ───────────── AST Walker ─────────────
fileprivate func clean(_ expr: ExprSyntax) -> String {
    let raw = expr.trimmed.description
    return raw.trimmingCharacters(in: .whitespacesAndNewlines)
              .replacingOccurrences(of: #"\s+"#, with: " ", options: [.regularExpression])
}
final class ASTWalker: SyntaxVisitor {
    let filePath: String
    var calls: [Call] = []
    private var currentFunction = "global"
    private var produced: [String:(String,[String],Int,String)] = [:]
    init(filePath: String) { self.filePath = filePath; super.init(viewMode:.sourceAccurate) }

    override func visit(_ node: FunctionDeclSyntax) -> SyntaxVisitorContinueKind {
        currentFunction = node.name.text; return .visitChildren
    }
    override func visit(_ node: VariableDeclSyntax) -> SyntaxVisitorContinueKind {
        for binding in node.bindings {
            guard let pat = binding.pattern.as(IdentifierPatternSyntax.self),
                  let initVal = binding.initializer?.value else { continue }
            let name = pat.identifier.text
            let line = binding.positionAfterSkippingLeadingTrivia.utf8Offset
            if let lit = initVal.as(StringLiteralExprSyntax.self) {
                produced[name] = ("literal", [], line, lit.segments.description)
            } else if let lit = initVal.as(IntegerLiteralExprSyntax.self) {
                produced[name] = ("literal", [], line, lit.description)
            } else if let ref = initVal.as(DeclReferenceExprSyntax.self) {
                if let src = produced[ref.baseName.text] { produced[name] = src }
            } else if let call = initVal.as(FunctionCallExprSyntax.self) {
                let apiName = clean(call.calledExpression)
                produced[name] = (apiName, [apiName], line, apiName)
            }
        }
        return .visitChildren
    }
    override func visit(_ node: FunctionCallExprSyntax) -> SyntaxVisitorContinueKind {
        var args:[Argument]=[]
        for arg in node.arguments {
            let v = clean(arg.expression)
            if let src = produced[v] {
                let t = src.0 == "literal" ? "constant" : "function_return"
                args.append(Argument(type:t,value:src.3,producedAs:v,trace:src.1))
            } else {
                args.append(Argument(type:"unknown",value:v,producedAs:nil,trace:nil))
            }
        }
        let line = node.positionAfterSkippingLeadingTrivia.utf8Offset
        let api  = clean(node.calledExpression)
        var prodAs:String? = nil
        var trc:[String]?  = nil

        if let first = args.first?.value {
            if IO_WRITE_APIS.contains(api) { prodAs = "IO#\(first)" }
            else if IO_READ_APIS.contains(api) {
                args[0] = Argument(type:"function_return", value:"IO#\(first)", producedAs:nil, trace:nil)
            }
            if EVT_PUB_APIS.contains(api) { prodAs = "EVT#\(first)" }
            else if EVT_SUB_APIS.contains(api) {
                args[0] = Argument(type:"function_return", value:"EVT#\(first)", producedAs:nil, trace:nil)
            }
        }
        if prodAs == nil {
            for (k,v) in produced where v.0==api && v.2==line { prodAs=k; trc=v.1; break }
        }
        calls.append(Call(api:api,
                          location:Location(file:filePath,line:line,function:currentFunction),
                          arguments:args, producedAs:prodAs, trace:trc))
        return .visitChildren
    }
}

// ───────────── Directory Scanning ─────────────
func childDirs(of path: String) -> [String] {
    let fm = FileManager.default
    guard let subs = try? fm.contentsOfDirectory(atPath: path) else { return [] }
    var out: [String] = []
    for s in subs {
        let p = path + "/" + s
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: p, isDirectory: &isDir), isDir.boolValue { out.append(p) }
    }
    return out
}
func findSwiftFolder(under dir: String) -> String? {
    for c in childDirs(of: dir) {
        if URL(fileURLWithPath: c).lastPathComponent.caseInsensitiveCompare("Swift") == .orderedSame {
            return c
        }
    }
    return nil
}
func hasSwiftFiles(_ dir: String) -> Bool {
    let fm = FileManager.default
    guard let en = fm.enumerator(atPath: dir) else { return false }
    for case let f as String in en { if f.lowercased().hasSuffix(".swift") { return true } }
    return false
}
func collectProjects(root: String) -> [String] {
    var projects: [String] = []
    for child in childDirs(of: root) {
        if let swiftDir = findSwiftFolder(under: child) {
            let subs = childDirs(of: swiftDir)
            var added = false
            for s in subs { if hasSwiftFiles(s) { projects.append(s); added = true } }
            if !added, hasSwiftFiles(swiftDir) { projects.append(swiftDir) }
        }
    }
    return projects
}
func swiftFiles(in dir:String)->[String]{
    var out:[String]=[]
    if let e = FileManager.default.enumerator(atPath:dir){
        for case let f as String in e where f.hasSuffix(".swift") {
            out.append("\(dir)/\(f)".replacingOccurrences(of:"\\",with:"/"))
        }
    }
    return out
}

// ───────────── Excel：PowerShell -EncodedCommand ─────────────
func fmtHMS(_ interval: TimeInterval) -> String {
    let ms = Int((interval.truncatingRemainder(dividingBy: 1)) * 1000.0)
    let s  = Int(interval) % 60
    let m  = (Int(interval) / 60) % 60
    let h  = Int(interval) / 3600
    return String(format: "%02d:%02d:%02d.%03d", h, m, s, ms)
}
enum ExcelAppendError: Error, CustomStringConvertible {
    case powershellNotFound
    case powershellFailed(Int32, String, String)
    var description: String {
        switch self {
        case .powershellNotFound: return "Cannot find Windows PowerShell（powershell.exe）"
        case .powershellFailed(let c, let o, let e):
            return "PowerShell fail（code \(c)）\nSTDOUT:\n\(o)\nSTDERR:\n\(e)"
        }
    }
}
func env(_ key: String) -> String? { ProcessInfo.processInfo.environment[key] }
func findWindowsPowerShell() -> String? {
    if let sys = env("SystemRoot") ?? env("WINDIR") {
        let p1 = sys + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        if FileManager.default.fileExists(atPath: p1) { return p1 }
        let p2 = sys + "\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
        if FileManager.default.fileExists(atPath: p2) { return p2 }
    }
    return nil 
}
func psEscapeSingleQuoted(_ s: String) -> String { s.replacingOccurrences(of: "'", with: "''") }

func appendPerProjectToExcel(excelPath: String, project: String, elapsed: TimeInterval) throws {
    #if os(Windows)
    guard let psExe = findWindowsPowerShell() else { throw ExcelAppendError.powershellNotFound }

    let ms  = String(format: "%.4f", elapsed * 1000.0).replacingOccurrences(of: ",", with: ".")
    let sec = String(format: "%.6f", elapsed).replacingOccurrences(of: ",", with: ".")
    let hms = fmtHMS(elapsed)

    let xlsx = psEscapeSingleQuoted(excelPath.replacingOccurrences(of: "\\", with: "/"))
    let proj = psEscapeSingleQuoted(project)

    let script = """
$ErrorActionPreference = "Stop"
$excelPath = '\(xlsx)'
$project   = '\(proj)'
$ms = [double]'\(ms)'
$sec = [double]'\(sec)'
$hms = '\(hms)'

$xl = New-Object -ComObject Excel.Application
$xl.Visible = $false
$xl.DisplayAlerts = $false
try {
  if (Test-Path -LiteralPath $excelPath) {
    $wb = $xl.Workbooks.Open([ref]$excelPath)
  } else {
    $dir = Split-Path -LiteralPath $excelPath
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $wb = $xl.Workbooks.Add()
    $wb.SaveAs($excelPath, 51)
  }

  $sheet = $null
  foreach ($ws in $wb.Worksheets) { if ($ws.Name -eq "PerProject") { $sheet = $ws; break } }
  if (-not $sheet) {
    $sheet = $wb.Worksheets.Add()
    $sheet.Name = "PerProject"
    $sheet.Range("A1:E1").NumberFormat = "@"
    $sheet.Range("A1").Value2="Index"
    $sheet.Range("B1").Value2="Project"
    $sheet.Range("C1").Value2="Elapsed (ms)"
    $sheet.Range("D1").Value2="Elapsed (seconds)"
    $sheet.Range("E1").Value2="Elapsed (hh:mm:ss.fff)"
  }

  $row = ($sheet.Cells.Item($sheet.Rows.Count,1)).End(-4162).Row + 1  # xlUp
  if ($row -lt 2) { $row = 2 }

  $sheet.Range("A$($row)").Value2 = [double]($row - 1)

  $cellB = $sheet.Range("B$($row)")
  $cellB.NumberFormat = "@"
  $cellB.Value2 = [string]$project

  $sheet.Range("C$($row)").Value2 = $ms
  $sheet.Range("D$($row)").Value2 = $sec

  $cellE = $sheet.Range("E$($row)")
  $cellE.NumberFormat = "@"
  $cellE.Value2 = [string]$hms

  $wb.Save()
} finally {
  if ($null -ne $wb) { $wb.Close($true) }
  $xl.Quit()
}
"""

    let data = script.data(using: .utf16LittleEndian)!
    let b64  = data.base64EncodedString()

    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: psExe)
    proc.arguments = ["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-EncodedCommand", b64]

    let outPipe = Pipe(), errPipe = Pipe()
    proc.standardOutput = outPipe
    proc.standardError  = errPipe
    try proc.run()
    proc.waitUntilExit()

    let outStr = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let errStr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    if proc.terminationStatus != 0 { throw ExcelAppendError.powershellFailed(proc.terminationStatus, outStr, errStr) }
    #else
    #endif
}

// ───────────── Main ─────────────
func main() {
    let argv = CommandLine.arguments
    guard argv.count >= 2 else {
        print("用法: swift run swift_ast_analyzer <根目录> [D:\\mcp_detection_results-v2\\run_times.xlsx]"); return
    }
    let rootDir = argv[1]
    let excelPath = argv.count >= 3 ? argv[2] : "D:\\mcp_detection_results-v2\\run_times.xlsx"

    let fm = FileManager.default
    guard fm.fileExists(atPath: rootDir) else { print("输入目录不存在：\(rootDir)"); return }


    let projects = collectProjects(root: rootDir)
    if projects.isEmpty {
        print("⚠️ Cannot find any Swift project"); return
    }
    print("✓ Find \(projects.count)  Swift project")

    let jsonOutDir = URL(fileURLWithPath: excelPath).deletingLastPathComponent().path
    if !fm.fileExists(atPath: jsonOutDir) {
        try? fm.createDirectory(atPath: jsonOutDir, withIntermediateDirectories: true)
    }

    let t0 = Date()
    for (i,p) in projects.enumerated() {
        var rel = URL(fileURLWithPath: p).path
        if rel.hasPrefix(rootDir) {
            rel = String(rel.dropFirst(rootDir.count)).trimmingCharacters(in: CharacterSet(charactersIn: "/\\"))
        }
        print("\n📁 [\(i+1)/\(projects.count)] \(rel)")
        let start = Date()

        var filesIR:[FileIR]=[]
        if let e = fm.enumerator(atPath: p) {
            for case let f as String in e where f.hasSuffix(".swift") {
                let full = p + "/" + f
                if let src = try? String(contentsOfFile: full, encoding: .utf8) {
                    let tree = Parser.parse(source: src)
                    let walker = ASTWalker(filePath: full.replacingOccurrences(of: "\\", with: "/"))
                    walker.walk(tree)
                    filesIR.append(FileIR(file: full.replacingOccurrences(of: "\\", with: "/"), calls: walker.calls))
                }
            }
        }

        // YAML pipeline
        let yPaths = ["\(p)/pipeline.yml","\(p)/pipeline.yaml"]
        if let yPath = yPaths.first(where:{ fm.fileExists(atPath:$0) }),
           let txt   = try? String(contentsOfFile:yPath),
           let yaml  = try? Yams.load(yaml:txt) as? [String:Any],
           let pipeline = yaml["pipeline"] as? [String] {
            var pseudo:[Call]=[]
            for (i,step) in pipeline.enumerated() {
                var a:[Argument]=[]
                if i>0 { a.append(Argument(type:"function_return", value:"PIPE#\(pipeline[i-1])", producedAs:nil, trace:nil)) }
                pseudo.append(Call(api:step,
                                   location:Location(file:"__pipeline__",line:i+1,function:"pipeline"),
                                   arguments:a, producedAs:"PIPE#\(step)", trace:[step]))
            }
            filesIR.append(FileIR(file:"__pipeline__",calls:pseudo))
        }


        var jw=JSONWriter(); jw.write(OutputRoot(project: URL(fileURLWithPath:p).lastPathComponent, files: filesIR))
        let json = jw.build()+"\n"
        let safeName = rel.replacingOccurrences(of: "\\", with: "_")
                          .replacingOccurrences(of: "/", with: "_")
                          .replacingOccurrences(of: ":", with: "_")
        let outPath="\(jsonOutDir)/\(safeName).json"
        try? json.write(to:URL(fileURLWithPath:outPath),atomically:true,encoding:.utf8)
        print("   ↳ JSON: \(outPath)")


        let elapsed = Date().timeIntervalSince(start)
        do {
            try appendPerProjectToExcel(excelPath: excelPath, project: "swift/\(rel)", elapsed: elapsed)
            print("   ⏱  Elapsed \(fmtHMS(elapsed)) → Writed \(excelPath)")
        } catch {
            print("❌ Write Excel Fail：\(error)")
            return
        }
    }

    print("\n🎉 Completed: Total \(projects.count) projects; Total time: \(fmtHMS(Date().timeIntervalSince(t0)))")
}

main()
