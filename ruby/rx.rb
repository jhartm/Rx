class Rx
  TAG_BASE = "tag:codesimply.com,2008:rx/"
  TAG_CORE = File.join(TAG_BASE, "core/")
  TAG_META = File.join(TAG_BASE, "meta/")

  def self.schema(schema)
    Rx.new(load_core: true).make_schema(schema)
  end

  def initialize(opt = {})
    @type_registry = {}
    @prefix = { "" => TAG_CORE, ".meta" => TAG_META }

    load_core if opt[:load_core]
  end
  
  def load_core
    Type::Core.core_types.each { |t| register_type(t) }
  end

  def register_type(type)
    uri = type.uri

    if @type_registry.has_key?(uri)
      raise Rx::Exception.new("attempted to register already-known type #{uri}")
    end

    @type_registry[uri] = type
  end

  def learn_type(uri, schema)
    if @type_registry.has_key?(uri)
      raise Rx::Exception.new("attempted to learn type for already-registered uri #{uri}")
    end

    # make sure schema is valid
    # should this be in a begin/rescue?
    make_schema(schema)

    @type_registry[uri] = { "schema" => schema }
  end

  def expand_uri(name)
    return name if name =~ /\A\w+:/

    match = name.match(/\A\/(.*?)\/(.+)\z/)

    unless match
      raise Rx::Exception.new("couldn't understand Rx type name: #{name}")
    end

    unless @prefix.has_key?(match[1])
      raise Rx::Exception.new("unknown prefix '#{match[1]}' in name '#{name}'")
    end

    return @prefix[match[1]] + match[2]
  end

  def add_prefix(name, base)
    if @prefix.has_key?(name)
      raise Rx::Exception.new("the prefix '#{name}' is already registered")
    end

    @prefix[name] = base
  end

  def make_schema(schema)
    schema = { "type" => schema } if schema.instance_of?(String)

    if schema.instance_of?(Array)
      sub_schemas = schema.select { |schemata| schemata["uri"] && schemata["schema"] }

      raise Rx::Exception.new("too many schemas detected") unless (schema - sub_schemas).size == 1

      schema = (schema - sub_schemas).first

      sub_schemas.each { |schemata| learn_type(schemata["uri"], schemata["schema"]) }
    end

    unless schema.instance_of?(Hash) && schema["type"]
      raise Rx::Exception.new("invalid type")
    end

    uri = expand_uri(schema["type"])

    raise Rx::Exception.new("unknown type") unless @type_registry.has_key?(uri)

    type_class = @type_registry[uri]

    return type_class.new(schema, self) unless type_class.instance_of?(Hash)

    return make_schema(type_class["schema"]) if schema.keys == ["type"]

    raise Rx::Exception.new("composed type does not take check arguments")
  end

  class Helper
    class Range
      def initialize(arg)
        @range = {}

        arg.each_pair do |key, value|
          unless ["min", "max", "min-ex", "max-ex"].index(key)
            raise Rx::Exception.new("illegal argument for #{self.class}")
          end

          @range[key] = value
        end
      end

      def check(value)
        return false unless @range["min"   ].nil? || value >= @range["min"   ]
        return false unless @range["min-ex"].nil? || value >  @range["min-ex"]
        return false unless @range["max-ex"].nil? || value <  @range["max-ex"]
        return false unless @range["max"   ].nil? || value <= @range["max"   ]
        return true
      end
    end
  end

  Exception = Class.new(StandardError)

  class ValidationError < StandardError
    attr_accessor :path

    def initialize(message, path)
      @message = message
      @path = path
    end

    def message
      "#{@message} (#{@path})"
    end

    def inspect
      "#{@message} (#{@path})"
    end

    def to_s
      inspect
    end
  end

  class Type
    BASE_PARAMS = ["type"].freeze
    REQUIRED_PARAMS = BASE_PARAMS
    OPTIONAL_PARAMS = []

    class << self
      def subname
        "/#{name.split("::").last.downcase}"
      end

      def uri
        File.join(TAG_CORE, subname)
      end
    end

    def subname
      self.class.subname
    end

    def uri
      self.class.uri
    end

    def check_params(required_params, optional_params, params)
      required_params.each do |required_param|
        unless params.include?(required_param)
          raise Rx::Exception.new("missing required parameter '#{required_param}' for uri #{uri}")
        end
      end

      params.each do |param|
        unless (required_params + optional_params).include?(param)
          raise Rx::Exception.new("unknown parameter '#{param}' for uri #{uri}")
        end
      end

      true
    end

    def has_schemata(params, key)
      if params[key].nil? || params[key].empty?
        raise Rx::Exception.new("no schemata provided for parameter '#{key}' in uri #{uri}")
      end

      true
    end

    def error(msg, path = subname)
      raise ValidationError.new(msg, path)
    end

    class Core < Type
      def check(value)
        begin
          check!(value)

          true
        rescue ValidationError
          false
        end
      end

      def validate(schema, value)
        begin
          return schema.check!(value)
        rescue ValidationError => e
          if block_given?
            yield(e)
          else
            e.path = subname + e.path
            raise e
          end
        end
      end

      class All < Core
        REQUIRED_PARAMS += ["of"]

        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)

          has_schemata(params, "of")

          @alts = []

          params["of"].each { |alt| @alts.push(rx.make_schema(alt)) }
        end

        def check!(value)
          @alts.each { |alt| validate(alt, value) }

          return true
        end
      end

      class Any < Core
        OPTIONAL_PARAMS += ["of"]

        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)

          return unless params.has_key?("of")

          has_schemata(params, "of")

          @alts = []

          params["of"].each { |alt| @alts.push(rx.make_schema(alt)) }
        end

        def check!(value)
          return true unless @alts

          @alts.each do |alt|
            return true if validate(alt, value) { }
          end

          error("expected one to match")
        end
      end

      class Arr < Core
        REQUIRED_PARAMS += ["contents"]
        OPTIONAL_PARAMS += ["length"]

        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)

          has_schemata(params, "contents")

          @contents_schema = rx.make_schema(params["contents"])

          return unless params.has_key?("length")

          @length_range = Rx::Helper::Range.new(params["length"])
        end

        def check!(value)
          unless value.is_a?(Array)
            error("expected array got #{value.class}")
          end

          if @length_range && !@length_range.check(value.length)
            error("expected array with #{@length_range} elements, got #{value.length}")
          end

          value.each { |v| validate(@contents_schema, v) } if @contents_schema

          return true
        end
      end

      class Bool < Core
        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)
        end

        def check!(value)
          return true if [TrueClass, FalseClass].include?(value.class)

          error("expected bool got #{value.inspect}")
        end
      end

      class Fail < Core
        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)
        end

        def check(value)
          false
        end

        def check!(value)
          error("explicit fail")
        end
      end

      #
      # Added by dan - 81030
      class Date < Core
        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)
        end

        def check!(value)
          return true if value.instance_of?(::Date)

          error("expected Date got #{value.inspect}")
        end
      end

      class Def < Core
        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)
        end

        def check!(value)
          error("def failed") if value.nil?
        end
      end

      class Map < Core
        REQUIRED_PARAMS += ["values"]

        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)

          has_schemata(params, "values")

          @value_schema = rx.make_schema(params["values"])
        end

        def check!(value)
          unless value.instance_of?(Hash) || value.class.to_s == "HashWithIndifferentAccess"
            error("expected map got #{value.inspect}")
          end

          value.each_value { |v| validate(@value_schema, v) } if @value_schema

          return true
        end
      end

      class Nil < Core
        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)
        end

        def check!(value)
          return true if value.nil?

          error("expected nil got #{value.inspect}")
        end
      end

      class Num < Core
        OPTIONAL_PARAMS += ["range", "value"]

        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)

          if params.has_key?("value")
            unless params["value"].is_a?(Numeric)
              raise Rx::Exception.new("invalid value parameter for #{uri}")
            end

            @value = params["value"]
          end

          return unless params.has_key?("range")

          @value_range = Rx::Helper::Range.new(params["range"])
        end

        def check!(value)
          unless value.is_a?(Numeric)
            error("expected Numeric got #{value.inspect}")
          end

          if @value_range && !@value_range.check(value)
            error("expected Numeric in range #{@value_range} got #{value.inspect}")
          end

          if @value && value != @value
            error("expected Numeric to equal #{@value} got #{value.inspect}")
          end

          true
        end
      end

      class Int < Num
        def initialize(params, rx)
          super

          return unless @value && !@value.is_a?(Integer)

          raise Rx::Exception.new("invalid value parameter for #{uri}")
        end

        def check!(value)
          super

          unless (value % 1).zero?
            error("expected Integer got #{value.inspect}")
          end

          return true
        end
      end

      class One < Core
        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)
        end

        def check!(value)
          return true if [Numeric, String, TrueClass, FalseClass].any? { |cls| value.is_a?(cls) }

          error("expected One got #{value.inspect}")
        end
      end

      class Rec < Core
        OPTIONAL_PARAMS += ["required", "optional", "rest"]

        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)

          @field = {}

          @rest_schema = rx.make_schema(params["rest"]) if params["rest"]

          ["optional", "required"].each do |type|
            next unless params[type]

            params[type].keys.each do |field|
              if @field[field]
                raise Rx::Exception.new("#{field} in both required and optional")
              end

              @field[field] = { :required => (type == "required"),
                                :schema   => rx.make_schema(params[type][field]) }
            end
          end
        end

        def check!(value)
          unless value.instance_of?(Hash) || value.class.to_s == "HashWithIndifferentAccess"
            error("expected Hash got #{value.class}")
          end

          rest = []

          value.each do |field, field_value|
            unless @field[field]
              rest.push(field)
              next
            end

            validate(@field[field][:schema], field_value) do |e|
              e.path = "#{subname}:'#{field}'"
              raise e
            end
          end

          @field.select { |k, v| @field[k][:required] }.each do |pair|
            unless value.has_key?(pair[0])
              error("expected Hash to have key: '#{pair[0]}', only had #{value.keys.inspect}")
            end
          end

          unless rest.empty?
            unless @rest_schema
              error("Hash had extra keys: #{rest.inspect}")
            end

            rest_hash = {}
            rest.each { |field| rest_hash[field] = value[field] }

            validate(@rest_schema, rest_hash) do |e|
              e.path = subname
              raise e
            end
          end

          return true
        end
      end

      class Seq < Core
        REQUIRED_PARAMS += ["contents"]
        OPTIONAL_PARAMS += ["tail"]

        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)

          has_schemata(params, "contents")

          @content_schemata = params["contents"].map { |s| rx.make_schema(s) }

          return unless params.has_key?("tail")

          @tail_schema = rx.make_schema(params["tail"])
        end

        def check!(value)
          unless value.is_a?(Array)
            error("expected Array got #{value.inspect}")
          end

          if value.length < @content_schemata.length
            error("expected Array to have at least #{@content_schemata.length} elements, had #{value.length}")
          end

          @content_schemata.each_with_index do |schemata, i|
            validate(schemata, value[i])
          end

          if value.length > @content_schemata.length
            unless @tail_schema
              error("expected tail schema")
            end

            validate(@tail_schema, value[@content_schemata.length, value.length - @content_schemata.length])
          end

          return true
        end
      end

      class Str < Core
        OPTIONAL_PARAMS += ["value", "length"]

        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)

          if params.has_key?("length")
            @length_range = Rx::Helper::Range.new(params["length"])
          end

          return unless params.has_key?("value")

          unless params["value"].is_a?(String)
            raise Rx::Exception.new("invalid value parameter for #{uri}")
          end

          @value = params["value"]
        end

        def check!(value)
          unless value.is_a?(String)
            error("expected String got #{value.inspect}")
          end

          if @length_range && !@length_range.check(value.length)
            error("expected string with #{@length_range} characters, got #{value.length}")
          end

          if @value && value != @value
            error("expected #{@value.inspect} got #{value.inspect}")
          end

          return true
        end
      end

      #
      # Added by dan - 81106
      class Time < Core
        def initialize(params, rx)
          check_params(REQUIRED_PARAMS, OPTIONAL_PARAMS, params.keys)
        end

        def check!(value)
          unless value.instance_of?(::Time)
            error("expected Time got #{value.inspect}")
          end

          true
        end
      end

      class << self
        def core_types
          [All,
           Any,
           Arr,
           Bool,
           Date,
           Def,
           Fail,
           Int,
           Map,
           Nil,
           Num,
           One,
           Rec,
           Seq,
           Str,
           Time]
        end
      end
    end
  end
end
