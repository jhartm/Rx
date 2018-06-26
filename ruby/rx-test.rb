#!/usr/bin/ruby
require 'rubygems'
require 'json'
require './ruby/Rx.rb'

test_data   = {}
test_schema = {}

Dir.glob('spec/data/*.json').each do |file|
  json = File.read(file)

  name = File.basename(file).sub(File.extname(file), '')

  test_data[name] = JSON.parse(json)

  if test_data[name].is_a?(Array)
    new_data = {}
    test_data[name].each { |e| new_data[e] = e }
    test_data[name] = new_data
  end

  test_data[name].each_pair do |k, v|
    test_data[name][k] = JSON.parse("[ #{v} ]")[0]
  end
end

def normalize(entries, test_data)
  entries = { "*" => nil } if entries == '*'

  if entries.kind_of?(Array)
    new_entries = {}
    entries.each { |n| new_entries[n].nil? }
    entries = new_entries
  end

  if entries.one? && entries.has_key?('*')
    value = entries["*"]
    entries = {}
    test_data.keys.each { |k| entries[k] = value }
  end

  return entries
end

class TAP_Emitter
  attr_reader :i
  attr_reader :failures

  def initialize
    @failures = 0
  end

  def ok(bool, desc)
    @i.nil? ? @i = 1 : @i += 1

    @failures += 1 unless bool

    printf("%s %s - %s\n", bool ? 'ok' : 'not ok', @i, desc)
  end
end

Dir.glob('spec/schemata/**/*.json').each do |file|
  json = File.read(file)

  name = File.basename(file).sub(File.extname(file), '')

  test_schema[name] = JSON.parse(json)
end

tap = TAP_Emitter.new

test_schema.keys.sort.each do |schema_name|
  rx = Rx.new(load_core: true)

  schema_test_desc = test_schema[schema_name]

  if schema_test_desc['composedtype']
    begin
      rx.learn_type(schema_test_desc['composedtype']['uri'],
                    schema_test_desc['composedtype']['schema'])
    rescue Rx::Exception => e
      if schema_test_desc['composedtype']['invalid']
        tap.ok(true, "BAD COMPOSED TYPE: #{schema_name}")
        next
      end

      raise e
    end

    if schema_test_desc['composedtype']['invalid']
      tap.ok(false, "BAD COMPOSED TYPE: #{schema_name}")
      next
    end

    if schema_test_desc['composedtype']['prefix']
      rx.add_prefix(schema_test_desc['composedtype']['prefix'][0],
                    schema_test_desc['composedtype']['prefix'][1])
    end
  end

  begin
    schema = rx.make_schema(schema_test_desc['schema'])
  rescue Rx::Exception => e
    if schema_test_desc['invalid']
      tap.ok(true, "BAD SCHEMA: #{schema_name}")
      next
    end

    raise e
  end

  unless schema
    tap.ok(false, "no schema for valid input (#{schema_name})")
    next
  end

  if schema_test_desc['invalid']
    tap.ok(false, "BAD SCHEMA: #{schema_name}")
    next
  end

  ['pass', 'fail'].each do |pf|
    next unless schema_test_desc[pf]

    schema_test_desc[pf].each_pair do |source, entries|
      entries = normalize(entries, test_data[source])

      entries.each_pair do |entry, want|
        result = schema.check(test_data[source][entry])
        ok = (pf == 'pass' && result) || (pf == 'fail' && !result)

        desc = "#{pf == 'pass' ? 'VALID  ' : 'INVALID'}: #{source}/#{entry} against #{schema_name}"

        tap.ok(ok, desc)
      end

      entries.each_pair do |entry, want|
        result = begin
          schema.check!(test_data[source][entry])
          true
        rescue Rx::ValidationError => e
          false
        end

        ok = (pf == 'pass' && result) || (pf == 'fail' && !result)

        desc = "#{pf == 'pass' ? 'VALID  ' : 'INVALID'}: #{source}-#{entry} against #{schema_name}"

        tap.ok(ok, desc)
      end
    end
  end
end

puts "1..#{tap.i}"
exit(tap.failures > 0 ? 1 : 0)
