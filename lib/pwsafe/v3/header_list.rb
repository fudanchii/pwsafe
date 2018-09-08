module Pwsafe
  module V3
    class HeaderList < FieldList
      def initialize
        super
        @tagclass = HeaderTagClass
      end

      def complete?
        @list.last.is_a?(EndType)
      end
    end
  end
end
