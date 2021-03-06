module Pwsafe
  class DecodeError < ArgumentError
    class << self
      def wrong_type(classname)
        DecodeError.new("Wrong file type for #{classname}")
      end

      def file_corrupt(classname)
        DecodeError.new("File likely corrupted for #{classname}")
      end

      def not_authenticated
        DecodeError.new("need to check password first")
      end

      def unexpected_eof
        DecodeError.new("Unexpected End of file")
      end
    end
  end
end
