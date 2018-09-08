module Pwsafe
  module V3
    class UUIDType < BytesType
      def to_str
        "#{hxf(@data[0..3])}-#{hxf(@data[4..5])}-#{hxf(@data[6..7])}-#{hxf(@data[8..9])}-#{hxf(@data[10..-1])}"
      end
    end
  end
end
