
const fs       = require("fs");
const path     = require("path");
const yaml     = require("js-yaml");
const parser   = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;

const LANGUAGE = "javascript";


function getMemberExpressionName(node) {
  if (!node) return "null";
  switch (node.type) {
    case "Identifier":       return node.name;
    case "ThisExpression":   return "this";
    case "Super":            return "super";
    case "MemberExpression": {
      const obj = getMemberExpressionName(node.object);
      const prop = node.computed
        ? `[${getMemberExpressionName(node.property)}]`
        : getMemberExpressionName(node.property);
      return `${obj}.${prop}`;
    }
    case "CallExpression":   return getMemberExpressionName(node.callee);
    default:                 return "unknown";
  }
}


function toCode(node) {
  try { return generate(node).code; }
  catch { return "[Unserializable]"; }
}

/* ──────────────── Literal / Arg parse ──────────────── */

function isLiteral(node) {
  return node && (
    node.type === "StringLiteral"  ||
    node.type === "NumericLiteral" ||
    node.type === "BooleanLiteral" ||
    node.type === "NullLiteral"
  );
}

function getLiteralValue(node) {
  if (!node) return null;
  if (node.type === "NullLiteral") return null;
  return node.value;
}

function analyzeLiteral(node) {
  if (!node) return { type: "unknown", value: "null", _trace: [] };

  if (isLiteral(node)) {
    return { type: "constant", value: getLiteralValue(node), _trace: [] };
  }

  if (node.type === "ArrayExpression") {
    return {
      type: "list_literal",
      value: node.elements.map(el =>
        el ? analyzeLiteral(el) : { type: "constant", value: null, _trace: [] }),
      _trace: []
    };
  }

  if (node.type === "ObjectExpression") {
    const obj = {};
    for (const prop of node.properties || []) {
      if (!prop || !prop.key) continue;
      const key = prop.key.name || prop.key.value ||
                  getMemberExpressionName(prop.key) || "unknown";
      obj[key] = analyzeLiteral(prop.value);
    }
    return { type: "dict_literal", value: obj, _trace: [] };
  }

  return { type: "unknown", value: node.type || "null", _trace: [] };
}

class SymbolTableStack {
  constructor() { this.stack = [{}]; }
  current()     { return this.stack[this.stack.length - 1]; }
  push()        { this.stack.push({}); }
  pop()         { this.stack.pop(); }
  set(name,val) { this.current()[name] = val; }
  resolve(name) {
    for (let i = this.stack.length - 1; i >= 0; i--) {
      if (this.stack[i][name]) return this.stack[i][name];
    }
    return null;
  }
}

function analyzeArg(node, symbolTables) {
  if (!node) return { type: "unknown", value: "null", _trace: [] };

  if (isLiteral(node)) return {
    type: "constant", value: getLiteralValue(node), _trace: []
  };
  if (node.type === "ArrayExpression" || node.type === "ObjectExpression")
    return analyzeLiteral(node);

  if (node.type === "Identifier") {
    const resolved = symbolTables.resolve(node.name);
    if (resolved) return resolved;
    return { type: "variable", value: node.name, origin: "unknown", _trace: [] };
  }

  if (node.type === "CallExpression")
    return { type: "function_return", value: toCode(node), _trace: [toCode(node)] };

  if (["MemberExpression","LogicalExpression",
       "BinaryExpression","ConditionalExpression"].includes(node.type))
    return { type: "expression", value: toCode(node), _trace: [] };

  return { type: "unknown", value: node.type || "null", _trace: [] };
}


const IO_WRITE_APIS = new Set([
  "fs.writeFile",
  "fs.writeFileSync",
  "fs.appendFile",
  "fs.appendFileSync",
  "fs.createWriteStream",

  "file_put_contents",

  "JSON.stringify",

  "console.log",
  "console.info",
  "console.warn",
  "console.error",

  "winston.log",
  "pino.info",
  "bunyan.info"
]);

const IO_READ_APIS = new Set([
  "fs.readFile",
  "fs.readFileSync",
  "fs.createReadStream",

  "file_get_contents",

  "JSON.parse",

  "require",
  "import"
]);


const EVT_PUB_APIS = new Set([

  "bus.emit",
  "eventEmitter.emit",

  "publish",
  "window.dispatchEvent",
  "self.postMessage",

  // WebSocket
  "socket.send",
  "ws.send",

  // Redis / Kafka / MQTT
  "redisClient.publish",
  "kafkaProducer.send",
  "mqttClient.publish"
]);

const EVT_SUB_APIS = new Set([
  "bus.on",
  "eventEmitter.on",
  "eventEmitter.addListener",

  "subscribe",
  "addEventListener",

  // WebSocket
  "socket.on",
  "ws.on",

  // Redis / Kafka / MQTT
  "redisClient.subscribe",
  "kafkaConsumer.on",
  "mqttClient.on"
]);


/* ──────────────── AST → Call IR ──────────────── */

const FUNC_TYPES = [
  "FunctionDeclaration","FunctionExpression","ArrowFunctionExpression",
  "ClassMethod","ObjectMethod"
];

function extractCallsFromSource(filePath, sourceCode) {
  let ast;
  try {
    ast = parser.parse(sourceCode, {
      sourceType: "unambiguous",
      plugins: [
        "jsx","typescript","decorators-legacy","classProperties","classPrivateProperties",
        "classPrivateMethods","dynamicImport","exportDefaultFrom","importAssertions",
        "topLevelAwait","nullishCoalescingOperator","optionalChaining",
      ],
    });
  } catch (e) {
    console.warn(`⚠️ Parse error in ${filePath}: ${e.message}`);
    return [];
  }

  const calls = [];
  const st    = new SymbolTableStack();
  let current = null;

  traverse(ast, {
    enter(path) {
      if (FUNC_TYPES.includes(path.type)) {
        current = path.node.id ? (path.node.id.name || "anon") : "anon";
        st.push();
      }
    },
    exit(path) {
      if (FUNC_TYPES.includes(path.type)) {
        st.pop();
        current = null;
      }
    },

    VariableDeclaration(path) {
      for (const decl of path.node.declarations || []) {
        if (decl.id.type !== "Identifier") continue;
        const varName = decl.id.name;
        if (!decl.init) continue;

        if (decl.init.type === "CallExpression") {
          const callee = getMemberExpressionName(decl.init.callee);
          st.set(varName, {
            type: "function_return",
            value: callee,
            produced_as: varName,
            _trace: [callee],
          });
        } else {
          const lit = analyzeArg(decl.init, st);
          lit.produced_as = varName;
          st.set(varName, lit);
        }
      }
    },

    AssignmentExpression(path) {
      const { left, right } = path.node;
      if (right.type === "CallExpression" && left.type === "Identifier") {
        const callee = getMemberExpressionName(right.callee);
        st.set(left.name, {
          type: "function_return",
          value: callee,
          produced_as: left.name,
          _trace: [callee],
        });
      }
    },

    CallExpression(path) {
      const node = path.node;
      const func = getMemberExpressionName(node.callee);

      const argsObj = {};
      (node.arguments || []).forEach((arg, idx) => {
        if (!arg) return;
        let label = `arg${idx + 1}`;
        if (["Identifier","CallExpression","MemberExpression",
             "LogicalExpression","BinaryExpression","ConditionalExpression"].includes(arg.type)) {
          label = toCode(arg);
        }
        const argVal = analyzeArg(arg, st);
        if (argVal.type === "function_return") argVal._trace = [argVal.value];
        argsObj[label] = argVal;
      });

      const firstArg = node.arguments?.[0];
      const key      = firstArg && isLiteral(firstArg) ? firstArg.value
                       : firstArg ? toCode(firstArg) : "unknown";

      if (IO_WRITE_APIS.has(func)) {
        const handle = `IO#${key}`;
        calls.push({
          api: func,
          produced_as: handle,
          location: {
            file: filePath,
            line: node.loc?.start.line || null,
            function: current || "global",
          },
          arguments: argsObj,
          trace: [func],
        });
        return; 
      }

      if (IO_READ_APIS.has(func)) {
        const handle = `IO#${key}`;
        argsObj["path"] = { type: "function_return", value: handle, _trace: [] };
      }

      if (EVT_PUB_APIS.has(func)) {
        const topic = key;
        calls.push({
          api: func,
          produced_as: `EVT#${topic}`,
          location: {
            file: filePath,
            line: node.loc?.start.line || null,
            function: current || "global",
          },
          arguments: argsObj,
          trace: [func],
        });
        return;
      }

      if (EVT_SUB_APIS.has(func)) {
        const topic = key;
        argsObj["topic"] = {
          type: "function_return",
          value: `EVT#${topic}`,
          _trace: []
        };
      }

      let producedAs = null;
      for (let i = st.stack.length - 1; i >= 0; i--) {
        for (const [varName, info] of Object.entries(st.stack[i])) {
          if (info?.type === "function_return" &&
              info.value === func &&
              info.produced_as === varName) {
            producedAs = varName;
            break;
          }
        }
        if (producedAs) break;
      }

      const callIR = {
        api: func,
        location: {
          file: filePath,
          line: node.loc?.start.line || null,
          function: current || "global",
        },
        arguments: argsObj,
        trace: [func],
      };
      if (producedAs) callIR.produced_as = producedAs;
      calls.push(callIR);
    },

    /* ---------- Promise .then(callback) ---------- */
    MemberExpression(path) {
      if (
        path.node.property?.name === "then" &&
        path.parentPath?.node?.type === "CallExpression"
      ) {
        const thenCall = path.parentPath.node;
        const cb = thenCall.arguments[0];
        if (cb && (cb.type === "Identifier" || cb.type === "ArrowFunctionExpression")) {
          const cbName = cb.type === "Identifier" ? cb.name : "(arrow)";
          calls.push({
            api: cbName,
            location: {
              file: filePath,
              line: cb.loc?.start.line || null,
              function: current || "global",
            },
            arguments: {
              arg1: {
                type: "function_return",
                value: toCode(path.node.object),
                _trace: [],
              },
            },
            trace: [cbName],
          });
        }
      }
    },
  });

  return calls;
}

function extractPipelineIR(projectDir) {
  const yamlFile = ["pipeline.yaml", "pipeline.yml"]
    .map(f => path.join(projectDir, f))
    .find(fs.existsSync);
  if (!yamlFile) return [];

  let doc;
  try { doc = yaml.load(fs.readFileSync(yamlFile, "utf8")); }
  catch (e) {
    console.warn(`⚠️ YAML parse error ${yamlFile}: ${e.message}`);
    return [];
  }

  if (!Array.isArray(doc?.pipeline)) return [];
  const stages = doc.pipeline.map(s => String(s));
  const nodes = [];

  stages.forEach((stage, idx) => {
    const handle = `PIPE#${stage}`;
    const pseudoFile = `__pipeline__/${path.basename(yamlFile)}`;

    if (idx === 0) {
      nodes.push({
        api: stage,
        produced_as: handle,
        location: { file: pseudoFile, line: idx + 1, function: "pipeline" },
        arguments: {},
        trace: [stage],
      });
    } else {
      nodes.push({
        api: stage,
        produced_as: handle,
        location: { file: pseudoFile, line: idx + 1, function: "pipeline" },
        arguments: {
          in: { type: "function_return", value: `PIPE#${stages[idx - 1]}`, _trace: [] },
        },
        trace: [stage],
      });
    }
  });

  return nodes;
}


function walkDirRecursive(dir, acc = []) {
  fs.readdirSync(dir).forEach(f => {
    const full = path.join(dir, f);
    const st = fs.statSync(full);
    if (st.isDirectory()) {
      if (f === "node_modules" || f.startsWith(".")) return;
      walkDirRecursive(full, acc);
    } else if (
      (f.endsWith(".js") || f.endsWith(".ts")) &&
      !f.endsWith(".d.ts") &&
      !full.includes("node_modules") &&
      !/(_next|static|chunks|dist|build)/.test(full)
    ) {
      acc.push(full);
    }
  });
  return acc;
}

function processFile(filePath) {
  try {
    const code = fs.readFileSync(filePath, "utf8");
    return extractCallsFromSource(filePath, code);
  } catch (e) {
    console.warn(`⚠️ Read error ${filePath}: ${e.message}`);
    return [];
  }
}

function main() {
  if (process.argv.length < 4) {
    console.error("Usage: node extract_ir_all_projects.js <PROJECTS_ROOT_DIR> <OUTPUT_DIR>");
    process.exit(1);
  }

  const ROOT = process.argv[2];
  const OUT  = process.argv[3];
  if (!fs.existsSync(OUT)) fs.mkdirSync(OUT, { recursive: true });

  fs.readdirSync(ROOT)
    .map(name => path.join(ROOT, name))
    .filter(p => fs.statSync(p).isDirectory())
    .forEach(projectPath => {
      const projectName = path.basename(projectPath);
      const outputFile  = path.join(OUT, `${projectName}.json`);

      console.log(`📦 Extracting IR for ${projectName}`);

      const files   = walkDirRecursive(projectPath);
      const irFiles = [];

      files.forEach(f => {
        const calls = processFile(f);
        if (calls.length) irFiles.push({ file: f, calls });
      });

      const pipelineCalls = extractPipelineIR(projectPath);
      if (pipelineCalls.length) {
        irFiles.push({ file: "__pipeline__", calls: pipelineCalls });
      }

      if (!irFiles.length) {
        console.log(`⚠️ Skip ${projectName}, no calls.`);
        return;
      }

      const resultIR = { project: projectName, language: LANGUAGE, files: irFiles };
      try {
        fs.writeFileSync(outputFile, JSON.stringify(resultIR, null, 2), "utf8");
        console.log(`✅ Saved → ${outputFile}`);
      } catch (e) {
        console.error(`❌ Write fail ${outputFile}: ${e.message}`);
      }
    });

  console.log("🎉 All projects processed.");
}

main();
