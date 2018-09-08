module Pwsafe
  module V3
    class TextType < BytesType
      def to_str
        @data.force_encoding("UTF-8")
      end
    end
  end
end
