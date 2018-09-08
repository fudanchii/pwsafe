module Pwsafe
  module V3
    class Uint32Type < BytesType
      def initialize(chunk, label = "uint32 (no label)")
        super
        @data = uint32(@data)
      end

      def to_str
        @data.to_str
      end
    end
  end
end
