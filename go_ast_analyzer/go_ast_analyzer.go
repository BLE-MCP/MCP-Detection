package main

import (
	segmentjson "github.com/segmentio/encoding/json"
	"gopkg.in/yaml.v3"

	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type Location struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function,omitempty"`
}

type Argument struct {
	Type       string      `json:"type"`
	Value      interface{} `json:"value"`
	ProducedAs string      `json:"produced_as,omitempty"`
	Origin     string      `json:"origin,omitempty"`
	Trace      []string    `json:"_trace,omitempty"`
}

type Call struct {
	API      string              `json:"api"`
	Location Location            `json:"location"`
	Args     map[string]Argument `json:"-"`
	ArgOrder []string            `json:"-"`
	Trace    []string            `json:"trace,omitempty"`
	Produced string              `json:"produced_as,omitempty"`
}

type FileIR struct {
	File  string `json:"file"`
	Calls []Call `json:"calls"`
}

type ProjectIR struct {
	Project  string   `json:"project"`
	Language string   `json:"language"`
	Files    []FileIR `json:"files"`
}

type SymbolTable struct{ stack []map[string]Argument }

func NewSymbolTable() *SymbolTable                              { return &SymbolTable{stack: []map[string]Argument{{}}} }
func (s *SymbolTable) Push()                                    { s.stack = append(s.stack, map[string]Argument{}) }
func (s *SymbolTable) Pop()                                     { if len(s.stack) > 1 { s.stack = s.stack[:len(s.stack)-1] } }
func (s *SymbolTable) Set(n string, v Argument)                 { s.stack[len(s.stack)-1][n] = v }
func (s *SymbolTable) Resolve(n string) (Argument, bool)        { for i := len(s.stack) - 1; i >= 0; i-- { if v, ok := s.stack[i][n]; ok { return v, true } }; return Argument{}, false }

type CallVisitor struct {
	filepath string
	calls    []Call
	fset     *token.FileSet
	syms     *SymbolTable
	curFn    string
}

func NewCallVisitor(fp string, fset *token.FileSet) *CallVisitor {
	return &CallVisitor{filepath: fp, fset: fset, syms: NewSymbolTable()}
}

var ioWriteAPIs = map[string]struct{}{
	"os.WriteFile":          {},
	"ioutil.WriteFile":      {},       
	"(*os.File).Write":      {},
	"(*bufio.Writer).Write": {},
	"(*bufio.Writer).WriteString": {},

	"encoding/json.Encoder.Encode": {},
	"encoding/xml.Encoder.Encode":  {},
	"(*gob.Encoder).Encode":        {},

	"log.Print":   {},
	"log.Println": {},
	"log.Printf":  {},
}

var ioReadAPIs = map[string]struct{}{
	"os.ReadFile":          {},
	"ioutil.ReadFile":      {},
	"(*os.File).Read":      {},
	"(*bufio.Reader).Read": {},
	"(*bufio.Reader).ReadString": {},
	"(*bufio.Scanner).Scan": {},

	"encoding/json.Decoder.Decode": {},
	"encoding/xml.Decoder.Decode":  {},
	"(*gob.Decoder).Decode":        {},
}

var evtPubAPIs = map[string]struct{}{
	"bus.Emit":     {},
	"bus.Publish":  {},

	"nats.Conn.Publish":  {},
	"redis.Client.Publish": {},

	// Websocket
	"(*websocket.Conn).WriteMessage": {},
	"(*websocket.Conn).WriteJSON":    {},

	// gRPC
	"(*grpc.ClientConn).Invoke": {},
}

var evtSubAPIs = map[string]struct{}{
	"bus.On":        {},
	"bus.Subscribe": {},

	"nats.Conn.Subscribe":      {},
	"redis.PubSub.Receive":     {},
	"redis.PubSub.Channel":     {},

	// Websocket
	"(*websocket.Conn).ReadMessage": {},
	"(*websocket.Conn).ReadJSON":    {},

	// gRPC
	"(*grpc.Server).Serve": {},
}


/* ---------- AST ---------- */
func (v *CallVisitor) Visit(node ast.Node) ast.Visitor {
	switch n := node.(type) {

	case *ast.FuncDecl:
		v.curFn = n.Name.Name
		v.syms.Push()
		if n.Body != nil {
			ast.Walk(v, n.Body)
		}
		v.syms.Pop()
		v.curFn = ""
		return nil

	case *ast.AssignStmt:
		v.handleAssign(n)
	case *ast.CallExpr:
		v.handleCall(n, "")
	}
	return v
}


func (v *CallVisitor) handleAssign(a *ast.AssignStmt) {
	for i := 0; i < len(a.Lhs) && i < len(a.Rhs); i++ {
		target := exprToString(a.Lhs[i])
		switch rhs := a.Rhs[i].(type) {
		case *ast.CallExpr:
			api := exprToString(rhs.Fun)
			arg := Argument{Type: "function_return", Value: api, ProducedAs: target, Trace: []string{api}}
			v.syms.Set(target, arg)
			v.handleCall(rhs, target)
		default:
			if lit := analyzeLiteral(rhs); lit.Type != "unknown" {
				v.syms.Set(target, lit)
			}
		}
	}
}


func (v *CallVisitor) handleCall(call *ast.CallExpr, producedAs string) {
	api := exprToString(call.Fun)

	pos := v.fset.Position(call.Pos())
	c := Call{
		API: api,
		Location: Location{
			File:     v.filepath,
			Line:     pos.Line,
			Function: v.curFn,
		},
		Args:     map[string]Argument{},
		ArgOrder: []string{},
		Trace:    []string{api},
	}

	for i, arg := range call.Args {
		label := fmt.Sprintf("arg%d", i+1)
		c.ArgOrder = append(c.ArgOrder, label)
		c.Args[label] = v.analyzeArg(arg)
	}


	if len(call.Args) > 0 {
		key := exprToString(call.Args[0])
		if _, ok := ioWriteAPIs[api]; ok {
			c.Produced = "IO#" + key
		}
		if _, ok := ioReadAPIs[api]; ok {
			c.Args["path"] = Argument{Type: "function_return", Value: "IO#" + key}
		}
		if _, ok := evtPubAPIs[api]; ok {
			c.Produced = "EVT#" + key
		}
		if _, ok := evtSubAPIs[api]; ok {
			c.Args["topic"] = Argument{Type: "function_return", Value: "EVT#" + key}
		}
	}

	if producedAs != "" {
		c.Produced = producedAs
		if res, ok := v.syms.Resolve(producedAs); ok {
			c.Trace = res.Trace
		}
	}

	v.calls = append(v.calls, c)
}

func (v *CallVisitor) analyzeArg(expr ast.Expr) Argument {
	switch e := expr.(type) {
	case *ast.BasicLit, *ast.CompositeLit:
		return analyzeLiteral(e)
	case *ast.Ident:
		if res, ok := v.syms.Resolve(e.Name); ok {
			return res
		}
		return Argument{Type: "variable", Value: e.Name, Origin: "unknown"}
	default:
		return Argument{Type: "expression", Value: exprToString(e)}
	}
}

func analyzeLiteral(node ast.Node) Argument {
	switch n := node.(type) {
	case *ast.BasicLit:
		return Argument{Type: "constant", Value: n.Value}
	case *ast.CompositeLit:
		if len(n.Elts) == 0 {
			return Argument{Type: "list_literal", Value: []interface{}{}}
		}
		obj := map[string]Argument{}
		for _, elt := range n.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				obj[exprToString(kv.Key)] = analyzeLiteral(kv.Value)
			}
		}
		return Argument{Type: "dict_literal", Value: obj}
	default:
		return Argument{Type: "unknown", Value: fmt.Sprintf("%T", node)}
	}
}

/* ---------- utils ---------- */
func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprToString(e.X) + "." + e.Sel.Name
	default:
		return strings.TrimSpace(fmt.Sprintf("%s", e))
	}
}

/* ----------  Ordered map for stable JSON ---------- */
func (c Call) OrderedArgumentsMap() map[string]interface{} {
	out, used := map[string]interface{}{}, map[string]bool{}
	for _, k := range c.ArgOrder {
		if v, ok := c.Args[k]; ok {
			out[k] = v
			used[k] = true
		}
	}
	for k, v := range c.Args {
		if !used[k] {
			out[k] = v
		}
	}
	return out
}

func walkDir(dir string) ([]FileIR, error) {
	var files []FileIR
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			fset := token.NewFileSet()
			if f, parseErr := parser.ParseFile(fset, path, nil, 0); parseErr == nil {
				visitor := NewCallVisitor(path, fset)
				ast.Walk(visitor, f)
				if len(visitor.calls) > 0 {
					files = append(files, FileIR{File: path, Calls: visitor.calls})
				}
			}
		}
		return nil
	})
	return files, nil
}

/* ---------- YAML pipeline ---------- */
func parsePipelineYaml(projectDir string) ([]Call, bool) {
	var ymlPath string
	for _, name := range []string{"pipeline.yaml", "pipeline.yml"} {
		if _, err := os.Stat(filepath.Join(projectDir, name)); err == nil {
			ymlPath = filepath.Join(projectDir, name)
			break
		}
	}
	if ymlPath == "" {
		return nil, false
	}
	data, _ := os.ReadFile(ymlPath)
	var node interface{}
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, false
	}

	stagesIface := func() []interface{} {
		if m, ok := node.(map[string]interface{}); ok {
			if arr, ok2 := m["pipeline"].([]interface{}); ok2 {
				return arr
			}
		}
		if arr, ok := node.([]interface{}); ok {
			return arr
		}
		return nil
	}()

	if len(stagesIface) == 0 {
		return nil, false
	}
	stages := []string{}
	for _, s := range stagesIface {
		stages = append(stages, fmt.Sprintf("%v", s))
	}

	calls := []Call{}
	for i, stg := range stages {
		call := Call{
			API: stg,
			Location: Location{
				File:     "__pipeline__/" + filepath.Base(ymlPath),
				Line:     i + 1,
				Function: "pipeline",
			},
			Args:     map[string]Argument{},
			Produced: "PIPE#" + stg,
			Trace:    []string{stg},
		}
		if i > 0 {
			call.Args["in"] = Argument{Type: "function_return", Value: "PIPE#" + stages[i-1]}
			call.ArgOrder = []string{"in"}
		}
		calls = append(calls, call)
	}
	return calls, true
}

/* ---------- Main ---------- */
func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <source_dir> <output_dir>")
		return
	}
	root := os.Args[1]
	outDir := os.Args[2]

	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		projectPath := filepath.Join(root, entry.Name())
		fmt.Printf("📁 Project: %s\n", entry.Name())

		filesIR, _ := walkDir(projectPath)

		if pipeCalls, ok := parsePipelineYaml(projectPath); ok {
			filesIR = append(filesIR, FileIR{File: "__pipeline__", Calls: pipeCalls})
		}

		var filesOut []struct {
			File  string                 `json:"file"`
			Calls []map[string]interface{} `json:"calls"`
		}
		for _, f := range filesIR {
			var callsOut []map[string]interface{}
			for _, c := range f.Calls {
				callsOut = append(callsOut, map[string]interface{}{
					"api":         c.API,
					"location":    c.Location,
					"arguments":   c.OrderedArgumentsMap(),
					"trace":       c.Trace,
					"produced_as": c.Produced,
				})
			}
			filesOut = append(filesOut, struct {
				File  string                   `json:"file"`
				Calls []map[string]interface{} `json:"calls"`
			}{File: f.File, Calls: callsOut})
			fmt.Printf("%s (%d calls)\n", f.File, len(f.Calls))
		}


		outFile := filepath.Join(outDir, entry.Name()+".json")
		os.MkdirAll(filepath.Dir(outFile), os.ModePerm)
		f, _ := os.Create(outFile)
		enc := segmentjson.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]interface{}{
			"project":  entry.Name(),
			"language": "go",
			"files":    filesOut,
		})
		_ = f.Close()
		fmt.Printf("✅  Output → %s\n", outFile)
	}
}
