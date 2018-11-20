require "date"

module Pwsafe
  module V3
    class TimeType < Uint32Type
      def to_str
        Time.at(@data).to_datetime.to_s
      end
    end
  end
end
