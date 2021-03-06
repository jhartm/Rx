#!/usr/bin/ruby
require 'rubygems'
require 'json'
require './ruby/Rx.rb'

DATA_DIR = "spec/data/"
SCHEMATA_DIR = "spec/schemata/"

test_data   = {}
test_schema = {}

Dir.glob(File.join(DATA_DIR, "*.json")).each do |file|
  json = File.read(file)

  name = File.basename(file).sub(File.extname(file), "")

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
  entries = { "*" => nil } if entries == "*"

  if entries.is_a?(Array)
    new_entries = {}
    entries.each { |n| new_entries[n] = nil }
    entries = new_entries
  end

  if entries.one? && entries.has_key?("*")
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
    @i = 0
    @failures = 0
  end

  def ok(bool, desc)
    @i += 1

    @failures += 1 unless bool

    puts "#{bool ? "ok" : "not ok"} #{@i} - #{desc}\n"
  end
end

Dir.glob(File.join(SCHEMATA_DIR, "**/*.json")).each do |file|
  json = File.read(file)

  name = file.sub(SCHEMATA_DIR, "").sub(File.extname(file), "")

  test_schema[name] = JSON.parse(json)
end

tap = TAP_Emitter.new

test_schema.keys.sort.each do |schema_name|
  rx = Rx.new(load_core: true)

  schema_test_desc = test_schema[schema_name]

  if schema_test_desc["composedtype"]
    begin
      rx.learn_type(schema_test_desc["composedtype"]["uri"],
                    schema_test_desc["composedtype"]["schema"])
    rescue Rx::Exception => e
      if schema_test_desc["composedtype"]["invalid"]
        tap.ok(true, "BAD COMPOSED TYPE: #{schema_name}")
        next
      end

      raise e
    end

    if schema_test_desc["composedtype"]["invalid"]
      tap.ok(false, "BAD COMPOSED TYPE: #{schema_name}")
      next
    end

    if schema_test_desc["composedtype"]["prefix"]
      rx.add_prefix(schema_test_desc["composedtype"]["prefix"][0],
                    schema_test_desc["composedtype"]["prefix"][1])
    end
  end

  begin

    schema = rx.make_schema(schema_test_desc["schema"])
  rescue Rx::Exception => e
    if schema_test_desc["invalid"]
      tap.ok(true, "BAD SCHEMA: #{schema_name}")
      next
    end

    raise e
  end

  unless schema
    tap.ok(false, "no schema for valid input (#{schema_name})")
    next
  end

  if schema_test_desc["invalid"]
    tap.ok(false, "BAD SCHEMA: #{schema_name}")
    next
  end

  ["pass", "fail"].each do |pf|
    valid_string = (pf == "pass" ? "VALID  " : "INVALID")

    next unless schema_test_desc[pf]

    schema_test_desc[pf].each_pair do |source, entries|
      entries = normalize(entries, test_data[source])

      entries.each_pair do |entry, want|
        result = schema.check(test_data[source][entry])
        ok = (pf == "pass" && result) || (pf == "fail" && !result)

        desc = "#{valid_string}: #{source}/#{entry} against #{schema_name}"

        tap.ok(ok, desc)
      end

      entries.each_pair do |entry, want|
        result = begin
                   schema.check!(test_data[source][entry])
                   true
                 rescue Rx::ValidationError => e
                   false
                 end

        ok = (pf == "pass" && result) || (pf == "fail" && !result)

        desc = "#{valid_string}: #{source}-#{entry} against #{schema_name}"

        tap.ok(ok, desc)
      end
    end
  end
end

puts "1..#{tap.i}"
exit(tap.failures > 0 ? 1 : 0)
