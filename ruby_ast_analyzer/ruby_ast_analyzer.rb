#!/usr/bin/env ruby
require 'parser/current'
require 'json'
require 'yaml'
require 'find'
require 'fileutils'
require 'set'

IO_WRITE_APIS = Set[

  'os.WriteFile',
  'ioutil.WriteFile',               
  '(*os.File).Write',
  '(*bufio.Writer).Write',
  '(*bufio.Writer).WriteString',


  'encoding/json.Encoder.Encode',
  'encoding/xml.Encoder.Encode',
  '(*gob.Encoder).Encode',


  'log.Print',
  'log.Println',
  'log.Printf'
].freeze

IO_READ_APIS = Set[

  'os.ReadFile',
  'ioutil.ReadFile',
  '(*os.File).Read',
  '(*bufio.Reader).Read',
  '(*bufio.Reader).ReadString',
  '(*bufio.Scanner).Scan',

  'encoding/json.Decoder.Decode',
  'encoding/xml.Decoder.Decode',
  '(*gob.Decoder).Decode'
].freeze

EVT_PUB_APIS = Set[

  'bus.Emit',
  'bus.Publish',


  'nats.Conn.Publish',
  'redis.Client.Publish',

  # WebSocket
  '(*websocket.Conn).WriteMessage',
  '(*websocket.Conn).WriteJSON',

  # gRPC 
  '(*grpc.ClientConn).Invoke'
].freeze

EVT_SUB_APIS = Set[

  'bus.On',
  'bus.Subscribe',


  'nats.Conn.Subscribe',
  'redis.PubSub.Receive',
  'redis.PubSub.Channel',

  # WebSocket
  '(*websocket.Conn).ReadMessage',
  '(*websocket.Conn).ReadJSON',

  # gRPC
  '(*grpc.Server).Serve'
].freeze


LANGUAGE = 'ruby'


def expr_to_s(node)
  return 'null' if node.nil?

  case node.type
  when :const, :lvar, :ivar, :cvar, :gvar
    node.children[1] || node.children[0] # const 有两级
  when :sym
    ":#{node.children[0]}"
  when :str
    "\"#{node.children[0]}\""
  when :int, :float
    node.children[0].to_s
  when :send
    recv = node.children[0] ? "#{expr_to_s(node.children[0])}." : ''
    args = node.children[2..].map { |a| expr_to_s(a) }.join(', ')
    "#{recv}#{node.children[1]}(#{args})"
  else
    node.type.to_s
  end
end


class SymbolTableStack
  def initialize
    @stack = [{}]
  end

  def push = @stack.push({})
  def pop  = @stack.pop
  def set(name, val) = @stack[-1][name] = val

  def resolve(name)
    @stack.reverse_each { |tbl| return tbl[name] if tbl.key?(name) }
    nil
  end
end

# ────────────────────────── analyze_arg ──────────
def analyze_arg(node, symtab)
  return { 'type' => 'unknown', 'value' => 'null', '_trace' => [] } if node.nil?

  if %i[int float str sym].include?(node.type)
    val = case node.type
          when :str then "\"#{node.children[0]}\""
          when :sym then ":#{node.children[0]}"
          else node.children[0].to_s
          end
    return { 'type' => 'constant', 'value' => val, '_trace' => [] }
  end

  if node.type == :lvar
    var = node.children[0].to_s
    resolved = symtab.resolve(var)
    return resolved if resolved

    return { 'type' => 'variable', 'value' => var, '_trace' => [] }
  end

  if node.type == :send
    return { 'type' => 'function_return', 'value' => expr_to_s(node), '_trace' => [expr_to_s(node)] }
  end

  { 'type' => 'expression', 'value' => expr_to_s(node), '_trace' => [] }
end

# ────────────────────────── AST ──────────────────────────
def analyze_ast(file_path, ast, calls)
  symtab = SymbolTableStack.new
  current_method = 'global'

  rec = lambda do |node|
    return unless node.is_a?(Parser::AST::Node)

    # -------- Function definition entry/exit --------
    if node.type == :def
      current_method = node.children[0].to_s
      symtab.push
    end

    # -------- Variable assignment --------
    if node.type == :lvasgn
      var = node.children[0].to_s
      rhs = node.children[1]

      if rhs&.type == :send
        symtab.set(var, {
                     'type' => 'function_return',
                     'value' => expr_to_s(rhs),
                     'produced_as' => var,
                     '_trace' => [expr_to_s(rhs)]
                   })
      elsif %i[str int float sym].include?(rhs&.type)
        symtab.set(var, {
                     'type' => 'constant',
                     'value' => expr_to_s(rhs),
                     '_trace' => []
                   })
      elsif rhs&.type == :lvar
        ref = symtab.resolve(rhs.children[0].to_s)
        symtab.set(var, ref) if ref
      end
    end

    # -------- Call Node --------
    if node.type == :send
      func_full = expr_to_s(node)                # e.g. File.read("a.txt")
      recv_name = expr_to_s(node.children[0])    

      api_str   = node.children[0] ? "#{recv_name}.#{node.children[1]}" : node.children[1].to_s
      loc_line  = node.location.expression.line

       args_hash = {}
      (node.children[2..] || []).each_with_index do |arg, idx|
        label = "arg#{idx + 1}"
        arg_info = analyze_arg(arg, symtab)
      
        if arg_info['type'] == 'variable' &&
           (resolved = symtab.resolve(arg_info['value']))
          arg_info = resolved
        end
        args_hash[label] = arg_info
      end

      first_arg = node.children[2]
      path_key  = first_arg ? expr_to_s(first_arg) : 'unknown'
      if IO_WRITE_APIS.include?(api_str)
        handle = "IO##{path_key}"
        symtab.set(handle, { 'type' => 'function_return', 'value' => handle, 'produced_as' => handle, '_trace' => [] })
      elsif IO_READ_APIS.include?(api_str)
        handle = "IO##{path_key}"
        args_hash['path'] = { 'type' => 'function_return', 'value' => handle, '_trace' => [] }
      end
 
      if EVT_PUB_APIS.include?(api_str)
        topic = first_arg ? expr_to_s(first_arg) : 'unknown'
        handle = "EVT##{topic}"
        symtab.set(handle, { 'type' => 'function_return', 'value' => handle, 'produced_as' => handle, '_trace' => [] })
      elsif EVT_SUB_APIS.include?(api_str)
        topic = first_arg ? expr_to_s(first_arg) : 'unknown'
        args_hash['topic'] = { 'type' => 'function_return', 'value' => "EVT##{topic}", '_trace' => [] }
      end

      produced_as = symtab.resolve(api_str)&.dig('produced_as')

      call_entry = {
        'api' => api_str,
        'location' => {
          'file' => file_path,
          'line' => loc_line,
          'function' => current_method
        },
        'arguments' => args_hash
      }
      call_entry['produced_as'] = produced_as if produced_as
      call_entry['trace'] = [api_str] if produced_as

      calls << call_entry
    end

    node.children.each { |c| rec.call(c) if c.is_a?(Parser::AST::Node) }

    symtab.pop if node.type == :def
  end

  rec.call(ast)
end

# ────────────────────────── YAML pipeline → IR ──────────────────────────
def extract_pipeline_ir(project_dir)
  yaml_file = %w[pipeline.yml pipeline.yaml].map { |f| File.join(project_dir, f) }
                                            .find { |f| File.exist?(f) }
  return [] unless yaml_file

  doc = YAML.load_file(yaml_file) rescue nil
  return [] unless doc.is_a?(Hash) && doc['pipeline'].is_a?(Array)

  stages = doc['pipeline'].map(&:to_s)
  nodes = []
  stages.each_with_index do |stage, idx|
    handle = "PIPE##{stage}"
    pseudo_file = "__pipeline__/#{File.basename(yaml_file)}"
    if idx.zero?
      nodes << {
        'api' => stage,
        'produced_as' => handle,
        'location' => { 'file' => pseudo_file, 'line' => idx + 1, 'function' => 'pipeline' },
        'arguments' => {},
        'trace' => [stage]
      }
    else
      nodes << {
        'api' => stage,
        'produced_as' => handle,
        'location' => { 'file' => pseudo_file, 'line' => idx + 1, 'function' => 'pipeline' },
        'arguments' => {
          'in' => { 'type' => 'function_return', 'value' => "PIPE##{stages[idx - 1]}", '_trace' => [] }
        },
        'trace' => [stage]
      }
    end
  end
  nodes
end


def ruby_files(dir)
  arr = []
  Find.find(dir) { |p| arr << p if File.file?(p) && File.extname(p) == '.rb' }
  arr
end


projects_root = ARGV[0] || '.'
output_dir    = ARGV[1] || File.join(__dir__, 'output')
abort "❌ Directory does not exist: #{projects_root}" unless Dir.exist?(projects_root)
FileUtils.mkdir_p(output_dir)

Dir.children(projects_root)
   .map { |d| File.join(projects_root, d) }
   .select { |p| File.directory?(p) }
   .each do |project_dir|

  project_name = File.basename(project_dir)
  puts "📦 Processing projects: #{project_name}"
  calls_per_file = []
  ruby_files(project_dir).each do |file_path|
    begin
      ast   = Parser::CurrentRuby.parse(File.read(file_path))
      calls = []
      analyze_ast(file_path, ast, calls)
      calls_per_file << { 'file' => file_path, 'calls' => calls }
    rescue => e
      warn "⚠️ Parsing failed #{file_path}: #{e.message}"
    end
  end


  pipeline_nodes = extract_pipeline_ir(project_dir)
  calls_per_file << { 'file' => '__pipeline__', 'calls' => pipeline_nodes } unless pipeline_nodes.empty?

  result_ir = { 'project' => project_name, 'language' => LANGUAGE, 'files' => calls_per_file }
  File.write(File.join(output_dir, "#{project_name}.json"), JSON.pretty_generate(result_ir))
  puts "✅ Output #{project_name}.json"
end

puts "🎉 All projects have been processed."
