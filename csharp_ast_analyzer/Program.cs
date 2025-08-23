// CSharpAstExtractor.csproj
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using ClosedXML.Excel;

namespace CSharpAstExtractor
{
    class Program
    {
        internal static readonly HashSet<string> IO_WRITE_APIS = new()
        {
            "File.WriteAllText", "File.WriteAllBytes", "Stream.Write",
            "Console.WriteLine", "Debug.WriteLine",
            "fs.writeFile", "fs.writeFileSync", "JSON.stringify"
        };
        internal static readonly HashSet<string> IO_READ_APIS = new()
        {
            "File.ReadAllText", "File.ReadAllBytes", "Stream.Read",
            "fs.readFile", "fs.readFileSync", "JSON.parse"
        };
        internal static readonly HashSet<string> EVT_PUB_APIS = new()
        {
            "EventBus.Publish", "Publish",
            "NotificationCenter.Post", "socket.Send", "redisClient.Publish"
        };
        internal static readonly HashSet<string> EVT_SUB_APIS = new()
        {
            "EventBus.Subscribe", "Subscribe",
            "NotificationCenter.AddObserver", "socket.On", "redisClient.Subscribe"
        };
   

        static void Main(string[] args)
        {
            string rootDir   = args.Length > 0 ? args[0] : ".";
            string outputDir = args.Length > 1 ? args[1] : Path.Combine(Directory.GetCurrentDirectory(), "output");

            if (!Directory.Exists(rootDir))
            {
                Console.Error.WriteLine($"❌ Directory does not exist:{rootDir}");
                return;
            }
            Directory.CreateDirectory(outputDir);

            var csharpRoots = FindCSharpRoots(rootDir);
            if (csharpRoots.Count == 0)
            {
                Console.WriteLine("⚠️ No folder named 'C#' was found in the given directory.");
                return;
            }
   
            var projectDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var csRoot in csharpRoots)
                foreach (var p in FindProjectsUnderCSharpRoot(csRoot))
                    projectDirs.Add(p);

            var projects = projectDirs.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
            int totalProjects = projects.Count;
            if (totalProjects == 0)
            {
                Console.WriteLine("⚠️ No C# projects were detected (neither *.csproj nor one level of subdirectories containing .cs).");
                return;
            }

            Console.WriteLine($"🕒 Found {totalProjects} total projects in {csharpRoots.Count} "C#" directories, starting analysis...");

            var perProjectTimes = new List<(int Index, string Project, TimeSpan Elapsed)>();
            var milestoneTimes  = new List<(int ProjectsProcessed, TimeSpan CumulativeElapsed)>();
            int processed = 0, nextMilestone = 1000;
            TimeSpan cumulative = TimeSpan.Zero;

            var overallWatch = Stopwatch.StartNew();

            foreach (var subDir in projects)
            {
                string relPath  = Path.GetRelativePath(rootDir, subDir).Replace('\\', '/');
                string safeName = ToSafeFileName(relPath);

                var watch = Stopwatch.StartNew();
                var csFiles = Directory.GetFiles(subDir, "*.cs", SearchOption.AllDirectories);

                if (csFiles.Length > 0)
                {
                    var visitor = new CSharpCallVisitor();
                    foreach (var file in csFiles)
                    {
                        var tree = CSharpSyntaxTree.ParseText(File.ReadAllText(file));
                        visitor.SetCurrentFile(file);
                        visitor.Visit(tree.GetRoot());
                    }

                    // YAML pipeline
                    string yamlPath = Directory.GetFiles(subDir, "pipeline.y*ml", SearchOption.TopDirectoryOnly).FirstOrDefault();
                    if (yamlPath != null)
                    {
                        var stages = ParsePipelineStages(File.ReadAllText(yamlPath));
                        if (stages.Any())
                            visitor.Calls.AddRange(BuildPipelineCalls(stages, yamlPath));
                    }

                    var result = new JObject
                    {
                        ["project"]  = relPath,
                        ["language"] = "csharp",
                        ["files"]    = new JArray
                        {
                            new JObject
                            {
                                ["file"]  = "*multiple files*",
                                ["calls"] = new JArray(visitor.Calls)
                            }
                        }
                    };
                    string outPath = Path.Combine(outputDir, safeName + ".json");
                    File.WriteAllText(outPath, result.ToString(Formatting.Indented));
                }
                else
                {
                    
                }

                watch.Stop();
                processed++;
                perProjectTimes.Add((processed, relPath, watch.Elapsed));
                cumulative += watch.Elapsed;

                if (processed >= nextMilestone)
                {
                    milestoneTimes.Add((processed, cumulative));
                    nextMilestone += 1000;
                }

                PrintProgress(processed, totalProjects, overallWatch);
            }

            if (milestoneTimes.Count == 0 || milestoneTimes[^1].ProjectsProcessed != processed)
                milestoneTimes.Add((processed, cumulative));

            string excelPath = Path.Combine(outputDir, "run_times.xlsx");
            WriteExcel(perProjectTimes, milestoneTimes, excelPath);

            Console.WriteLine($"\n🧾 已写入 Excel：{excelPath}");
        }

        static void PrintProgress(int done, int total, Stopwatch overall)
        {
            if (total <= 0) return;
            double pct = (double)done / total;
            int barWidth = 30;
            int filled   = (int)Math.Round(barWidth * pct);
            string bar   = new string('#', Math.Min(filled, barWidth)) + new string('.', Math.Max(0, barWidth - filled));

            var elapsed = overall.Elapsed;
            TimeSpan eta = done > 0 ? TimeSpan.FromTicks((long)(elapsed.Ticks * ((double)total / done - 1))) : TimeSpan.Zero;

            Console.Write($"\r▶ {done}/{total}  {(pct*100):0.00}%  |{bar}|  Elapsed {elapsed:hh\\:mm\\:ss}  ETA {eta:hh\\:mm\\:ss}");
            if (done == total) Console.WriteLine();
        }

        static List<string> FindCSharpRoots(string rootDir)
        {
            var list = new List<string>();
            var rootInfo = new DirectoryInfo(rootDir);
            if (string.Equals(rootInfo.Name, "C#", StringComparison.OrdinalIgnoreCase))
                list.Add(rootDir);

            list.AddRange(
                Directory.EnumerateDirectories(rootDir, "*", SearchOption.AllDirectories)
                         .Where(d => string.Equals(new DirectoryInfo(d).Name, "C#", StringComparison.OrdinalIgnoreCase))
            );
            return list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        static IEnumerable<string> FindProjectsUnderCSharpRoot(string csharpRoot)
        {
            var results = new List<string>();

            foreach (var top in Directory.EnumerateDirectories(csharpRoot, "*", SearchOption.TopDirectoryOnly))
            {
                bool hasCsFiles = Directory.EnumerateFiles(top, "*.cs", SearchOption.AllDirectories).Any();
                if (hasCsFiles)
                    results.Add(top);
            }

            if (results.Count == 0 && Directory.EnumerateFiles(csharpRoot, "*.cs", SearchOption.AllDirectories).Any())
                results.Add(csharpRoot);

            return results;
        }


        static List<string> ParsePipelineStages(string yaml)
        {
            var list = new List<string>();
            var inSection = false;
            foreach (var line in yaml.Split('\n'))
            {
                if (!inSection && line.TrimStart().StartsWith("pipeline:"))
                {
                    inSection = true; continue;
                }
                if (inSection)
                {
                    var m = Regex.Match(line, @"-\s*(\w+)");
                    if (m.Success) list.Add(m.Groups[1].Value);
                    else if (!line.StartsWith(" ") && !line.StartsWith("-")) break;
                }
            }
            return list;
        }

        static IEnumerable<JObject> BuildPipelineCalls(List<string> stages, string yamlPath)
        {
            var arr = new List<JObject>();
            for (int i = 0; i < stages.Count; i++)
            {
                var args = new JObject();
                if (i > 0)
                    args["in"] = new JObject
                    {
                        ["type"]  = "function_return",
                        ["value"] = $"PIPE#{stages[i-1]}",
                        ["_trace"]= new JArray()
                    };

                arr.Add(new JObject
                {
                    ["api"] = stages[i],
                    ["location"] = new JObject
                    {
                        ["file"]     = yamlPath,
                        ["line"]     = i + 1,
                        ["function"] = "pipeline"
                    },
                    ["arguments"]   = args,
                    ["produced_as"] = $"PIPE#{stages[i]}",
                    ["trace"]       = new JArray(stages[i])
                });
            }
            return arr;
        }

        // === Write Excel ===
        static void WriteExcel(
            List<(int Index, string Project, TimeSpan Elapsed)> perProjectTimes,
            List<(int ProjectsProcessed, TimeSpan CumulativeElapsed)> milestoneTimes,
            string excelPath)
        {
            using var wb = new XLWorkbook();

            var ws1 = wb.Worksheets.Add("PerProject");
            ws1.Cell(1, 1).Value = "Index";
            ws1.Cell(1, 2).Value = "Project";
            ws1.Cell(1, 3).Value = "Elapsed (ms)";
            ws1.Cell(1, 4).Value = "Elapsed (seconds)";
            ws1.Cell(1, 5).Value = "Elapsed (hh:mm:ss.fff)";

            int r = 2;
            foreach (var row in perProjectTimes)
            {
                ws1.Cell(r, 1).Value = row.Index;
                ws1.Cell(r, 2).Value = row.Project;
                ws1.Cell(r, 3).Value = row.Elapsed.TotalMilliseconds;
                ws1.Cell(r, 4).Value = row.Elapsed.TotalSeconds;
                ws1.Cell(r, 5).Value = row.Elapsed.ToString(@"hh\:mm\:ss\.fff");
                r++;
            }
            ws1.Columns().AdjustToContents();

            var ws2 = wb.Worksheets.Add("CumulativeBy1000");
            ws2.Cell(1, 1).Value = "Projects Processed";
            ws2.Cell(1, 2).Value = "Cumulative (ms)";
            ws2.Cell(1, 3).Value = "Cumulative (seconds)";
            ws2.Cell(1, 4).Value = "Cumulative (hh:mm:ss.fff)";

            r = 2;
            foreach (var m in milestoneTimes)
            {
                ws2.Cell(r, 1).Value = m.ProjectsProcessed;
                ws2.Cell(r, 2).Value = m.CumulativeElapsed.TotalMilliseconds;
                ws2.Cell(r, 3).Value = m.CumulativeElapsed.TotalSeconds;
                ws2.Cell(r, 4).Value = m.CumulativeElapsed.ToString(@"hh\:mm\:ss\.fff");
                r++;
            }
            ws2.Columns().AdjustToContents();

            wb.SaveAs(excelPath);
        }

        static string ToSafeFileName(string s)
        {
            var cleaned = s.Replace(Path.DirectorySeparatorChar, '_')
                           .Replace(Path.AltDirectorySeparatorChar, '_');
            foreach (var bad in Path.GetInvalidFileNameChars())
                cleaned = cleaned.Replace(bad, '_');
            return cleaned;
        }
    }

    public class CSharpCallVisitor : CSharpSyntaxWalker
    {
        public List<JObject> Calls { get; } = new();
        private string currentFile = "";
        private string currentFunction = "global";
        private readonly Dictionary<string, dynamic> producedVars = new();

        public void SetCurrentFile(string path) => currentFile = path.Replace("\\", "/");

        public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
        {
            currentFunction = node.Identifier.Text;
            base.VisitMethodDeclaration(node);
            currentFunction = "global";
        }

        public override void VisitAssignmentExpression(AssignmentExpressionSyntax node) { /* unchanged… */ base.VisitAssignmentExpression(node); }
        public override void VisitVariableDeclarator(VariableDeclaratorSyntax node)     { /* unchanged… */ base.VisitVariableDeclarator(node); }

        public override void VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            var method = node.Expression.ToString();
            var line   = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

            var argsArr = new List<JProperty>();
            var formalArgs = node.ArgumentList.Arguments.ToList();
            for (int i = 0; i < formalArgs.Count; i++)
            {
                string key = $"arg{i+1}";
                var a = formalArgs[i];
                string valCode = a.ToString();

                if (a.Expression is IdentifierNameSyntax id && producedVars.TryGetValue(id.Identifier.Text, out var src))
                {
                    var argObj = new JObject
                    {
                        ["type"]  = src.source == "literal" ? "constant" : "function_return",
                        ["value"] = src.source == "literal" ? src.value  : src.source,
                        ["produced_as"] = id.Identifier.Text,
                        ["_trace"] = new JArray(src.trace)
                    };
                    argsArr.Add(new JProperty(key, argObj));
                }
                else
                {
                    argsArr.Add(new JProperty(key, new JObject
                    {
                        ["type"]  = "unknown",
                        ["value"] = valCode
                    }));
                }
            }

            string producedAs = null;
            if (formalArgs.Count > 0)
            {
                var firstArgVal = formalArgs[0].Expression.ToString().Trim('"')!;

                if (Program.IO_WRITE_APIS.Contains(method))
                    producedAs = $"IO#{firstArgVal}";
                else if (Program.IO_READ_APIS.Contains(method))
                    argsArr[0] = new JProperty("arg1", new JObject
                    {
                        ["type"]  = "function_return",
                        ["value"] = $"IO#{firstArgVal}",
                        ["_trace"]= new JArray()
                    });

                if (Program.EVT_PUB_APIS.Contains(method))
                    producedAs = $"EVT#{firstArgVal}";
                else if (Program.EVT_SUB_APIS.Contains(method))
                    argsArr[0] = new JProperty("arg1", new JObject
                    {
                        ["type"]  = "function_return",
                        ["value"] = $"EVT#{firstArgVal}",
                        ["_trace"]= new JArray()
                    });
            }

            if (producedAs == null)
                producedAs = producedVars.FirstOrDefault(p => p.Value.source == method && p.Value.line == line).Key;

            var call = new JObject
            {
                ["api"] = method,
                ["location"] = new JObject
                {
                    ["file"]     = currentFile,
                    ["line"]     = line,
                    ["function"] = currentFunction
                },
                ["arguments"] = new JObject(argsArr.ToArray())
            };

            if (!string.IsNullOrEmpty(producedAs))
            {
                call["produced_as"] = producedAs;
                call["trace"]       = new JArray { method };
            }

            Calls.Add(call);
            base.VisitInvocationExpression(node);
        }
    }
}
