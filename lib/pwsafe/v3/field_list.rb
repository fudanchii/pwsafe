module Pwsafe
  module V3
    class FieldList
      include Pwsafe::Utils

      attr_reader :list

      def initialize
        @tagclass = DataTagClass
        @list = []
      end

      def update_from_chunk(chunk)
        if @current_field&.chars_needed?
          append_to_current_field(chunk)
        else
          set_current_field(chunk)
        end
      end

      def populated?
        !@list.empty?
      end

      private

      def append_to_list(field)
        unless @current_field.chars_needed?
          @list << @current_field
          @current_field = nil
        end
      end

      def append_to_current_field(chunk)
        @current_field.append(chunk)
        append_to_list(@current_field)
      end

      def set_current_field(chunk)
        tag = chunk[4].ord
        @current_field = @tagclass[tag][:type]
          .new(chunk, @tagclass[tag][:name])
        append_to_list(@current_field)
      end
    end
  end
end
