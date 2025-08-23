package org.example;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.GenericVisitorAdapter;
import com.google.gson.GsonBuilder;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.*;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

public class Main {

    private static class CallInfo {
        String api;
        Location location;
        String produced_as;
        List<String> trace;
        Map<String, Object> arguments = new LinkedHashMap<>();
    }
    private static class Location { String file; int line; String function; }
    private static class ProjectIR { String project; String language = "java"; List<FileIR> files = new ArrayList<>(); }
    private static class FileIR { String file; List<CallInfo> calls = new ArrayList<>(); }

    public static final Set<String> IO_WRITE_APIS = Set.of(
            "Files.write","FileOutputStream.write","FileWriter.write","BufferedWriter.write",
            "PrintWriter.write","OutputStreamWriter.write",
            "ObjectMapper.writeValue","XmlMapper.writeValue","Gson.toJson",
            "Logger.info","Logger.debug","Logger.warn","Logger.error"
    );
    public static final Set<String> IO_READ_APIS = Set.of(
            "Files.readAllBytes","Files.readString","FileInputStream.<init>","FileReader.<init>",
            "BufferedReader.read","BufferedReader.readLine","InputStreamReader.read",
            "ObjectMapper.readValue","XmlMapper.readValue","Gson.fromJson",
            "Properties.load","ResourceBundle.getBundle"
    );
    public static final Set<String> EVT_PUB_APIS = Set.of(
            "EventBus.emit","EventBus.publish",
            "com.google.common.eventbus.EventBus.post",
            "ApplicationEventPublisher.publishEvent",
            "KafkaTemplate.send","JmsTemplate.send",
            "SimpMessagingTemplate.convertAndSend","WebSocketSession.sendMessage"
    );
    public static final Set<String> EVT_SUB_APIS = Set.of(
            "EventBus.on","EventBus.subscribe",
            "Subscribe",
            "ApplicationListener.onApplicationEvent",
            "KafkaListener","JmsListener",
            "WebSocketHandler.handleMessage","MessageMapping"
    );

    public static void main(String[] args) {
        String rootArg, outArg;
        if (args.length >= 2) {
            rootArg = args[0].trim();
            outArg  = args[1].trim();
        } else {
            Scanner sc = new Scanner(System.in);
            System.out.print("Root dir: "); rootArg = sc.nextLine().trim();
            System.out.print("Output dir or run_times.xlsx: "); outArg = sc.nextLine().trim();
        }

        Path root = Paths.get(rootArg);
        if (!Files.isDirectory(root)) {
            System.err.println("❌ Invalid root dir: " + root);
            return;
        }

        final Path excelPath, jsonOutDir;
        if (outArg.toLowerCase().endsWith(".xlsx")) {
            excelPath = Paths.get(outArg);
            jsonOutDir = excelPath.getParent() != null ? excelPath.getParent() : Paths.get(".");
        } else {
            jsonOutDir = Paths.get(outArg);
            excelPath = jsonOutDir.resolve("run_times.xlsx");
        }
        try { Files.createDirectories(jsonOutDir); } catch (IOException e) { System.err.println("mkdir output failed: " + e.getMessage()); return; }

        List<Path> javaRoots = findJavaRootsSecondLevel(root);
        if (javaRoots.isEmpty()) {
            System.out.println("⚠️ No second level folder named Java was found in the given directory.");
            return;
        }

        List<Path> projects = new ArrayList<>();
        for (Path jr : javaRoots) {
            projects.addAll(findProjectsUnderJavaRoot(jr));
        }
        if (projects.isEmpty()) {
            System.out.println("⚠️ No Java projects were detected.");
            return;
        }

        long total = projects.size();
        long startAll = System.nanoTime();

        for (int i = 0; i < projects.size(); i++) {
            Path proj = projects.get(i);
            String rel = safeRelPath(root, proj);
            if (rel.isEmpty()) rel = proj.toString();

            System.out.printf("%n📁 [%d/%d] Project: %s%n", i + 1, total, rel);
            long t0 = System.nanoTime();

            try {
                List<Path> javaFiles = listJavaFiles(proj);
                ProjectIR projectIR = new ProjectIR(); projectIR.project = rel;

                for (Path p : javaFiles) {
                    FileIR f = extractCallsFromFile(p.toFile());
                    if (!f.calls.isEmpty()) projectIR.files.add(f);
                }

                List<CallInfo> pipelineCalls = extractPipelineCalls(proj.toFile());
                if (!pipelineCalls.isEmpty()) {
                    FileIR pseudo = new FileIR();
                    pseudo.file = "__pipeline__";
                    pseudo.calls = pipelineCalls;
                    projectIR.files.add(pseudo);
                }

                Path outFile = jsonOutDir.resolve(safeFileName(rel) + ".json");
                try (Writer w = Files.newBufferedWriter(outFile)) {
                    var gson = new GsonBuilder().setPrettyPrinting().create();
                    gson.toJson(projectIR, w);
                }
                System.out.println("✅  Output → " + outFile);

            } catch (Exception ex) {
                System.err.println("⚠️ Failed to process project:" + ex.getMessage());
            }

            Duration elapsed = Duration.ofNanos(System.nanoTime() - t0);
            String projectLabel = "java/" + rel;
            try {
                appendExcelPerProject(excelPath, projectLabel, elapsed);
            } catch (Exception e) {
                System.err.println("Failed to write Excel: " + e.getMessage());
            }

            // 进度 & 预估
            Duration sofar = Duration.ofNanos(System.nanoTime() - startAll);
            long done = i + 1;
            long remain = projects.size() - done;
            Duration eta = done > 0 ? sofar.dividedBy(done).multipliedBy(remain) : Duration.ZERO;
            System.out.printf("⏱️  Elapsed %s  |  ETA %s%n", human(elapsed), human(eta));
        }

        System.out.printf("%n🎉 Completed, total %d items; total time taken: %s%n", total, human(Duration.ofNanos(System.nanoTime() - startAll)));
    }

    private static List<Path> findJavaRootsSecondLevel(Path root) {
        List<Path> roots = new ArrayList<>();
        try (DirectoryStream<Path> l1 = Files.newDirectoryStream(root)) {
            for (Path lvl1 : l1) {
                if (!Files.isDirectory(lvl1)) continue;
                try (DirectoryStream<Path> l2 = Files.newDirectoryStream(lvl1)) {
                    for (Path sub : l2) {
                        if (Files.isDirectory(sub) && sub.getFileName().toString().equalsIgnoreCase("Java")) {
                            roots.add(sub);
                        }
                    }
                } catch (IOException ignored) {}
            }
        } catch (IOException ignored) {}
        return roots;
    }

    private static List<Path> findProjectsUnderJavaRoot(Path javaRoot) {
        List<Path> projects = new ArrayList<>();
        try (DirectoryStream<Path> l1 = Files.newDirectoryStream(javaRoot)) {
            for (Path sub : l1) {
                if (!Files.isDirectory(sub)) continue;
                if (containsJavaFile(sub)) {
                    projects.add(sub);
                }
            }
        } catch (IOException ignored) {}
        if (projects.isEmpty() && containsJavaFile(javaRoot)) {
            projects.add(javaRoot);
        }
        return projects;
    }

    private static boolean containsJavaFile(Path dir) {
        final boolean[] found = {false};
        try {
            Files.walk(dir).forEach(p -> {
                if (found[0]) return;
                String name = p.getFileName() != null ? p.getFileName().toString().toLowerCase() : "";
                if (Files.isRegularFile(p) && name.endsWith(".java")) {
                    found[0] = true;
                }
            });
        } catch (IOException ignored) {}
        return found[0];
    }

    private static List<Path> listJavaFiles(Path dir) throws IOException {
        try (var s = Files.walk(dir)) {
            return s.filter(p -> Files.isRegularFile(p) && p.toString().toLowerCase().endsWith(".java"))
                    .collect(Collectors.toList());
        }
    }

    private static FileIR extractCallsFromFile(File file) {
        FileIR fi = new FileIR(); fi.file = file.getAbsolutePath();
        try {
            ParseResult<CompilationUnit> pr = new JavaParser().parse(file);
            if (pr.isSuccessful() && pr.getResult().isPresent())
                pr.getResult().get().accept(new CallVisitor(fi), null);
        } catch (Exception e) {
            System.err.println("⚠️ Parse fail " + file.getName() + " : " + e.getMessage());
        }
        return fi;
    }

    private static class CallVisitor extends GenericVisitorAdapter<Void, Void> {
        private final FileIR fileIR;
        private final Deque<Map<String, Map<String,Object>>> symStack = new ArrayDeque<>();
        private String curMethod = "<global>";

        CallVisitor(FileIR fi){ this.fileIR = fi; symStack.push(new HashMap<>()); }
        private Map<String, Map<String,Object>> curScope(){ return symStack.peek(); }

        @Override public Void visit(MethodDeclaration n, Void arg){
            curMethod = n.getNameAsString();
            symStack.push(new HashMap<>());
            super.visit(n,arg);
            symStack.pop();
            curMethod = "<global>";
            return null;
        }
        @Override public Void visit(VariableDeclarator n, Void arg){
            n.getInitializer().ifPresent(init ->
                    curScope().put(n.getNameAsString(), analyzeExpr(init)));
            return super.visit(n,arg);
        }
        @Override public Void visit(AssignExpr n, Void arg){
            if(n.getTarget().isNameExpr())
                curScope().put(n.getTarget().asNameExpr().getNameAsString(), analyzeExpr(n.getValue()));
            return super.visit(n,arg);
        }
        @Override public Void visit(MethodCallExpr n, Void arg){
            CallInfo ci = new CallInfo();
            String fullApi = n.getScope().map(s -> s.toString() + "." + n.getNameAsString())
                    .orElse(n.getNameAsString());
            ci.api = fullApi;

            Location loc = new Location();
            loc.file = fileIR.file;
            loc.line = n.getBegin().map(p->p.line).orElse(-1);
            loc.function = curMethod;
            ci.location = loc;

            for(int i=0;i<n.getArguments().size();i++){
                ci.arguments.put("arg"+(i+1), traceArg(n.getArgument(i)));
            }

            if(!n.getArguments().isEmpty()){
                Expression first = n.getArgument(0);
                String key = first.isStringLiteralExpr()
                        ? first.asStringLiteralExpr().asString()
                        : first.toString();
                if(IO_WRITE_APIS.contains(fullApi))   ci.produced_as = "IO#"+key;
                if(IO_READ_APIS.contains(fullApi))    ci.arguments.put("path", Map.of("type","function_return","value","IO#"+key));
            }
            if(!n.getArguments().isEmpty()){
                String topic = n.getArgument(0).isStringLiteralExpr()
                        ? n.getArgument(0).asStringLiteralExpr().asString()
                        : n.getArgument(0).toString();
                if(EVT_PUB_APIS.contains(fullApi))   ci.produced_as = "EVT#"+topic;
                if(EVT_SUB_APIS.contains(fullApi))   ci.arguments.put("topic", Map.of("type","function_return","value","EVT#"+topic));
            }

            String producedVar = producedVariable(n);
            if(producedVar!=null){
                ci.produced_as = producedVar;
                ci.trace = List.of(ci.api);
                curScope().put(producedVar, Map.of(
                        "type","function_return","value",ci.api,"trace",List.of(ci.api)
                ));
            }

            fileIR.calls.add(ci);
            return super.visit(n,arg);
        }

        private Map<String,Object> traceArg(Expression e){
            if(e.isStringLiteralExpr()||e.isIntegerLiteralExpr()||e.isBooleanLiteralExpr())
                return Map.of("type","constant","value",e.toString());
            if(e.isNameExpr()){
                String v=e.asNameExpr().getNameAsString();
                Map<String,Object> ref = resolveVar(v);
                return ref!=null ? ref : Map.of("type","variable","value",v);
            }
            if(e.isMethodCallExpr())
                return Map.of("type","function_return","value",e.asMethodCallExpr().getNameAsString());
            return Map.of("type","expression","value",e.toString());
        }
        private Map<String,Object> analyzeExpr(Expression e){
            if(e.isMethodCallExpr())
                return Map.of("type","function_return","value",e.asMethodCallExpr().getNameAsString());
            if(e.isStringLiteralExpr())
                return Map.of("type","constant","value",e.asStringLiteralExpr().asString());
            if(e.isNameExpr()){
                Map<String,Object> ref=resolveVar(e.asNameExpr().getNameAsString());
                return ref!=null?ref:Map.of("type","variable","value",e.toString());
            }
            return Map.of("type","expression","value",e.toString());
        }
        private Map<String,Object> resolveVar(String name){
            for (Iterator<Map<String, Map<String,Object>>> it=symStack.descendingIterator(); it.hasNext();){
                Map<String, Map<String,Object>> scope = it.next();
                if(scope.containsKey(name)) return scope.get(name);
            }
            return null;
        }
        private String producedVariable(MethodCallExpr call){
            Node p = call.getParentNode().orElse(null);
            if(p instanceof AssignExpr a && a.getTarget().isNameExpr())
                return a.getTarget().asNameExpr().getNameAsString();
            if(p instanceof VariableDeclarator vd) return vd.getNameAsString();
            return null;
        }
    }

    private static List<CallInfo> extractPipelineCalls(File projectDir){
        File yml = List.of("pipeline.yaml","pipeline.yml").stream()
                .map(f->new File(projectDir,f))
                .filter(File::exists).findFirst().orElse(null);
        if(yml==null) return List.of();

        Object yamlRoot;
        try (InputStream is = new FileInputStream(yml)) {
            yamlRoot = new Yaml().load(is);
        } catch (Exception e) {
            System.err.println("⚠️ YAML parse "+yml.getName()+": "+e.getMessage());
            return List.of();
        }

        List<?> stagesRaw = yamlRoot instanceof Map<?,?>
                ? (List<?>) ((Map<?,?>)yamlRoot).get("pipeline")
                : yamlRoot instanceof List<?> ? (List<?>) yamlRoot : List.of();
        if(stagesRaw==null || stagesRaw.isEmpty()) return List.of();

        List<CallInfo> out = new ArrayList<>();
        for(int i=0;i<stagesRaw.size();i++){
            String stage = String.valueOf(stagesRaw.get(i));
            CallInfo ci = new CallInfo();
            ci.api = stage;
            ci.produced_as = "PIPE#"+stage;

            Location loc = new Location();
            loc.file = "__pipeline__/"+yml.getName();
            loc.line = i+1;
            loc.function = "pipeline";
            ci.location = loc;

            if(i>0){
                ci.arguments.put("in", Map.of("type","function_return","value","PIPE#"+stagesRaw.get(i-1)));
            }
            out.add(ci);
        }
        return out;
    }

    private static void appendExcelPerProject(Path xlsx, String project, Duration elapsed) throws IOException {
        final String SHEET = "PerProject";
        XSSFWorkbook wb;
        XSSFSheet sheet;

        if (Files.notExists(xlsx)) {
            wb = new XSSFWorkbook();
            sheet = wb.createSheet(SHEET);
            Row h = sheet.createRow(0);
            h.createCell(0).setCellValue("Index");
            h.createCell(1).setCellValue("Project");
            h.createCell(2).setCellValue("Elapsed (ms)");
            h.createCell(3).setCellValue("Elapsed (seconds)");
            h.createCell(4).setCellValue("Elapsed (hh:mm:ss.fff)");
        } else {
            try (InputStream in = Files.newInputStream(xlsx)) {
                wb = new XSSFWorkbook(in);
            }
            sheet = wb.getSheet(SHEET);
            if (sheet == null) {
                sheet = wb.createSheet(SHEET);
                Row h = sheet.createRow(0);
                h.createCell(0).setCellValue("Index");
                h.createCell(1).setCellValue("Project");
                h.createCell(2).setCellValue("Elapsed (ms)");
                h.createCell(3).setCellValue("Elapsed (seconds)");
                h.createCell(4).setCellValue("Elapsed (hh:mm:ss.fff)");
            }
        }

        int last = sheet.getLastRowNum(); 
        boolean hasData = last >= 1 || (last == 0 && sheet.getRow(0) != null && sheet.getRow(1) != null);
        int nextRowIdx = hasData ? last + 1 : 1;
        int nextIndex = nextRowIdx - 1; 

        double ms  = elapsed.toNanos() / 1_000_000.0;
        double sec = elapsed.toNanos() / 1_000_000_000.0;
        String hms = human(elapsed);

        Row r = sheet.createRow(nextRowIdx);
        r.createCell(0).setCellValue(nextIndex);
        r.createCell(1).setCellValue(project);
        r.createCell(2).setCellValue(ms);
        r.createCell(3).setCellValue(sec);
        r.createCell(4).setCellValue(hms);

        try (OutputStream out = Files.newOutputStream(xlsx)) {
            wb.write(out);
        }
        wb.close();
    }

    private static String safeRelPath(Path root, Path p) {
        try {
            Path rel = root.toAbsolutePath().normalize().relativize(p.toAbsolutePath().normalize());
            String s = rel.toString().replace('\\','/');
            if (s.startsWith("/")) s = s.substring(1);
            return s;
        } catch (Exception e) {
            return p.toString().replace('\\','/');
        }
    }

    private static String safeFileName(String s) {
        String name = s.replace("\\","_").replace("/","_");
        for (String ch : new String[]{":","*","?","\"","<",">","|"}) {
            name = name.replace(ch, "_");
        }
        return name;
    }

    private static String human(Duration d) {
        long ms = d.toMillis();
        long hh = ms / 3600000; ms %= 3600000;
        long mm = ms / 60000;   ms %= 60000;
        long ss = ms / 1000;    ms %= 1000;
        return String.format("%02d:%02d:%02d.%03d", hh, mm, ss, ms);
    }
}
