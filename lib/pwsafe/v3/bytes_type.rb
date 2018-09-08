module Pwsafe
  module V3
    class BytesType
      include Pwsafe::Utils

      attr_reader :chars_needed, :data, :label, :length

      def initialize(chunk, label = "bytes (no label)")
        @length = uint32(chunk[0..3])
        @label = label
        if @length < 11
          @data = chunk[5..(@length + 4)].dup
          @chars_needed = 0
        else
          @data = chunk[5..-1].dup
          @chars_needed = @length - 11
        end
      end

      def chars_needed?
        chars_needed > 0
      end

      def to_str
        hxf @data
      end

      def to_s
        to_str
      end

      def append(chunk)
        return @data unless chars_needed?
        if @chars_needed > chunk.length
          @data << chunk.dup
          @chars_needed -= chunk.length
        else
          @data << chunk[0..@chars_needed - 1].dup
          @chars_needed = 0
        end
      end
    end
  end
end
