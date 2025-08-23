<?php
require 'vendor/autoload.php';

use PhpParser\{Node, NodeTraverser, NodeVisitorAbstract, ParserFactory, PhpVersion};
use Symfony\Component\Yaml\Yaml;

/* ───── CLI ───── */
$rootDir = $argv[1] ?? '.';
$outDir  = $argv[2] ?? (__DIR__ . '/output');
if (!is_dir($rootDir)) { echo "❌ Directory does not exist: $rootDir\n"; exit(1); }
if (!is_dir($outDir))  mkdir($outDir, 0777, true);

$IO_WRITE = [
    'file_put_contents',
    'fwrite',
    'fputs',
    'stream_socket_sendto',
    'stream_write',
    'fwritefile',
    'gzwrite',
    'bzwrite',
    'error_log',              
    'json_encode',            
];

$IO_READ = [
    'file_get_contents',
    'fread',
    'fgets',
    'stream_socket_recvfrom',
    'stream_get_contents',
    'gzread',
    'bzread',
    'readfile',
    'parse_ini_file',         
    'json_decode',          
    'require',
    'include',
];

$EVT_PUB = [
    'event_emit',
    'bus_emit',
    'publish',
    'event_dispatch',
    'socket_write',
    'mqtt_publish',
    'redis_publish',
    'amqp_publish',
];

$EVT_SUB = [
    'event_on',
    'bus_on',
    'subscribe',
    'add_listener',
    'socket_read',
    'mqtt_subscribe',
    'redis_subscribe',
    'amqp_consume',
];


foreach (array_filter(glob($rootDir . '/*'), 'is_dir') as $projectDir) {
    $project = basename($projectDir);
    echo "\n📁 Project: $project\n";

    $phpFiles = collectPhpFiles($projectDir);
    if (!$phpFiles) { echo "⚠️  No PHP files, skiping \n"; continue; }


    $pf = new ParserFactory();
    if (method_exists($pf, 'create')) {
        $parser = $pf->create(ParserFactory::PREFER_PHP7);                 // v4.x
    } elseif (method_exists($pf, 'createForLatestPhpVersion')) {
        $parser = $pf->createForLatestPhpVersion();                        // v5.3+
    } elseif (method_exists($pf, 'createForVersion')) {                    // v5.0–v5.2
        $verObj = method_exists(PhpVersion::class, 'fromComponents')
                ? PhpVersion::fromComponents(PHP_MAJOR_VERSION, PHP_MINOR_VERSION)
                : PhpVersion::fromString(PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION);
        $parser = $pf->createForVersion($verObj);
    } else {
        throw new RuntimeException('Unsupported nikic/php-parser version');
    }

    $filesIR  = [];
    $globVars = [];           

    foreach ($phpFiles as $filePath) {
        try {
            $ast = $parser->parse(file_get_contents($filePath));
        } catch (Throwable $e) {
            echo "⚠️  Fail to parse: $filePath\n"; continue;
        }

        $calls = [];
        $traverser = new NodeTraverser();
        $traverser->addVisitor(
            new class(
                $filePath, $calls, $globVars,
                $IO_WRITE, $IO_READ, $EVT_PUB, $EVT_SUB
            ) extends NodeVisitorAbstract {

                private string $file;
                private array  $calls;  
                private array  $vars;
                private string $curFn = 'global';

                private array $IOW; private array $IOR;
                private array $EPB; private array $ESB;

                public function __construct(
                    string $file,
                    array  &$calls,
                    array  &$vars,
                    array  $IOW,
                    array  $IOR,
                    array  $EPB,
                    array  $ESB
                ) {
                    $this->file  = $file;
                    $this->calls =& $calls;
                    $this->vars  =& $vars;
                    $this->IOW   = $IOW;
                    $this->IOR   = $IOR;
                    $this->EPB   = $EPB;
                    $this->ESB   = $ESB;
                }

                public function enterNode(Node $n) {
                    if ($n instanceof Node\Stmt\Function_) {
                        $this->curFn = $n->name->name;
                    }

                    if ($n instanceof Node\Expr\Assign) {
                        $lhs = $this->toStr($n->var);
                        $rhs = $n->expr;

                        if ($rhs instanceof Node\Expr\FuncCall
                            || $rhs instanceof Node\Expr\MethodCall
                            || $rhs instanceof Node\Expr\StaticCall) {

                            $api = $this->toStr($rhs);        
                            $this->vars[$lhs] = [
                                'source' => $api,
                                'trace'  => [$api],
                                'line'   => $n->getLine()
                            ];
                            $this->handleCall($rhs, $lhs);   
                        } elseif ($rhs instanceof Node\Scalar) {
                            $this->vars[$lhs] = [
                                'source'=>'literal',
                                'value' =>$this->toStr($rhs),
                                'trace' =>[],
                                'line'  =>$n->getLine()
                            ];
                        } elseif ($rhs instanceof Node\Expr\Variable) {
                            $from = $this->toStr($rhs);
                            if (isset($this->vars[$from])) $this->vars[$lhs] = $this->vars[$from];
                        }
                    }

                    if ($n instanceof Node\Expr\FuncCall && $n->name instanceof Node\Name) {
                        $this->handleCall($n, '');
                    }
                }

                private function handleCall(Node\Expr $node, string $producedAs) {
                    $api   = $this->nodeToName($node);   
                    if ($this->isPlaceholderName($api)) return;

                    $args  = [];

                    foreach ($node->args as $i => $arg) {
                        if (!$arg->value instanceof Node\Expr) continue;
                        $args['arg'.($i+1)] = $this->parseArg($arg->value);
                    }
                    
                    if ($node->args) {
                        $first = $node->args[0]->value ?? null;
                        $key   = $first instanceof Node\Expr ? $this->toStr($first) : 'unknown';

                        if (in_array($api, $this->IOW))  $producedAs = "IO#$key";
                        if (in_array($api, $this->IOR))  $args['path']  = ['type'=>'function_return','value'=>"IO#$key"];
                        if (in_array($api, $this->EPB))  $producedAs = "EVT#$key";
                        if (in_array($api, $this->ESB))  $args['topic'] = ['type'=>'function_return','value'=>"EVT#$key"];
                    }

                    $trace = $producedAs && isset($this->vars[$producedAs])
                           ? $this->vars[$producedAs]['trace']
                           : [$api];

                    $entry = [
                        'api'       => $api,
                        'location'  => [
                            'file'     => $this->file,
                            'line'     => $node->getLine(),
                            'function' => $this->curFn
                        ],
                        'arguments'   => $args,
                        'trace'       => $trace
                    ];
                    if ($producedAs) $entry['produced_as'] = $producedAs;

                    $this->calls[] = $entry;
                }

                private function parseArg(Node\Expr $e): array {
                    if ($e instanceof Node\Scalar ||
                         ($e instanceof Node\Expr\UnaryMinus && $e->expr instanceof Node\Scalar\LNumber) ||
                         ($e instanceof Node\Expr\UnaryPlus  && $e->expr instanceof Node\Scalar\LNumber)) {
                         return ['type'=>'constant','value'=>$this->toStr($e)];
                    }
                    if ($e instanceof Node\Expr\Variable) {
                        $v = $this->toStr($e);
                        if (isset($this->vars[$v])) {
                            $meta = $this->vars[$v];
                            if ($meta['source'] === 'literal') {
                                return [
                                    'type'       =>'constant',
                                    'value'      =>$meta['value'],
                                    'produced_as'=>$v,
                                    '_trace'     =>$meta['trace']
                                ];
                            }
                            return [
                                'type'       =>'function_return',
                                'value'      =>$meta['source'],
                                'produced_as'=>$v,
                                '_trace'     =>$meta['trace']
                            ];
                        }
                        return ['type'=>'variable','value'=>$v];
                    }
                    if ($e instanceof Node\Expr\FuncCall) {
                        return ['type'=>'function_call','value'=>$this->toStr($e->name)];
                    }
                    return ['type'=>'expression','value'=>$this->toStr($e)];
                }


                private function toStr(Node $e): string {
                    return match (true) {
                        $e instanceof Node\Expr\Variable  => '$'.(is_string($e->name)?$e->name:'?'),

                       /* $obj->method() */
                       $e instanceof Node\Expr\MethodCall =>
                           $this->toStr($e->var).'->'.$this->toStr($e->name),

                       /* ClassName::staticMethod() */
                       $e instanceof Node\Expr\StaticCall =>
                           $this->toStr($e->class).'::'.$this->toStr($e->name),

                        $e instanceof Node\Scalar\String_ => '"'.$e->value.'"',
                        $e instanceof Node\Scalar\LNumber => (string)$e->value,

                       $e instanceof Node\Expr\FuncCall  =>
                           $e->name instanceof Node\Name ? $e->name->toString() : 'call',

                        default => 'expr',
                    };
                }

                private function nodeToName(Node\Expr $call): string {
                    return match (true) {
                        $call instanceof Node\Expr\FuncCall   =>
                            $call->name instanceof Node\Name ? $call->name->toString() : 'call',
                        $call instanceof Node\Expr\MethodCall =>
                            $this->toStr($call->var) . '->' . $this->toStr($call->name),
                        $call instanceof Node\Expr\StaticCall =>
                            $this->toStr($call->class) . '::' . $this->toStr($call->name),
                        default => 'call',
                    };
                }

                private function isPlaceholderName(string $name):bool{
                    return str_contains($name,'expr') || str_contains($name,'?');
                }

            }
        );
        $traverser->traverse($ast);
        if ($calls) $filesIR[] = ['file'=>$filePath,'calls'=>$calls];
    }

    if ($pipe = parsePipelineYaml($projectDir)) $filesIR[] = $pipe;

    $jsonFile = "$outDir/{$project}_ir.json";
    file_put_contents($jsonFile, json_encode([
        'project'  => $project,
        'language' => 'php',
        'files'    => $filesIR
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    echo "✅  Output: $jsonFile\n";
}


function collectPhpFiles(string $dir): array {
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
    $out = [];
    foreach ($rii as $f) {
        if ($f->isFile() && strtolower($f->getExtension()) === 'php') {
            $out[] = $f->getPathname();
        }
    }
    return $out;
}

function parsePipelineYaml(string $dir): ?array {
    foreach (['pipeline.yml', 'pipeline.yaml'] as $name) {
        $path = "$dir/$name";
        if (!file_exists($path)) continue;

        $data = Yaml::parseFile($path);
        $stages = $data['pipeline'] ?? $data;
        if (!is_array($stages) || !$stages) return null;

        $calls = [];
        $prev  = null;
        $line  = 1;
        foreach ($stages as $stage) {
            $calls[] = [
                'api'       => $stage,
                'location'  => [
                    'file'     => "__pipeline__/$name",
                    'line'     => $line++,
                    'function' => 'pipeline'
                ],
                'arguments' => $prev
                              ? ['in' => ['type'=>'function_return','value'=>"PIPE#$prev"]]
                              : [],
                'produced_as' => "PIPE#$stage",
                'trace'       => [$stage]
            ];
            $prev = $stage;
        }
        return ['file'=>'__pipeline__','calls'=>$calls];
    }
    return null;
}
