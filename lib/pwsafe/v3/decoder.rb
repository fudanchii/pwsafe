require "openssl"
require "zweifische"

module Pwsafe
  module V3
    class Decoder
      include Pwsafe::Utils

      def initialize(filename = DEFAULT_PSAFE_FILE)
        @filename = filename

        File.open(@filename, "rb") do |f|
          assert_filetype(f.read(4))

          @salt = f.read(32) # 256 bit
          @iteration = uint32(f.read(4))
          @p_hash = f.read(32)
          @b1b2 = f.read(32)
          @b3b4 = f.read(32)
          @iv = f.read(16) # 128 bit
          @c_pos = f.pos

          f.pos = f.size - 48 # EOF + HMAC256
          assert_eof(f.read(16))
          @hmac = f.read(32)
        end
      end

      def validate_password(password)
        reset_keys
        OpenSSL::Digest::SHA256
          .digest(stretch_key(password, @iteration))
          .eql?(@p_hash) || reset_keys
      end

      def header
        return @header.list if @header.populated?
        list
        @header.list
      end

      def list
        return @fields.list if @fields.populated?

        File.open(@filename, "rb") do |f|
          f.pos = @c_pos

          loop do # decode header
            encblock = f.read(16)

            if encblock.eql?(EOF) || encblock.empty?
              raise DecodeError.unexpected_eof
            end

            chunk = decrypt_data(encblock)
            @header.update_from_chunk(chunk)
            break if @header.complete?
          end

          loop do # decode data
            encblock = f.read(16)

            break if encblock.eql?(EOF)
            raise DecodeError.unexpected_eof if encblock.empty?

            chunk = decrypt_data(encblock)
            @fields.update_from_chunk(chunk)
          end
        end

        @fields.list
      end

      def debug(password)
        puts "password : #{validate_password(password).inspect}"
        puts "salt     : #{hxf @salt}"
        puts "iteration: #{@iteration}"
        puts "p_hash   : #{hxf @p_hash}"
        puts "p        : #{hxf @stretch_key}"
        puts "hash(p)  : #{hxf OpenSSL::Digest::SHA256.digest(@stretch_key)}"
        puts "b1b2     : #{hxf @b1b2}"
        puts "b3b4     : #{hxf @b3b4}"
        puts "K        : #{hxf _k}"
        puts "L        : #{hxf _l}"
        puts "iv       : #{hxf @iv}"
        puts "c_pos    : #{@c_pos}"
        puts "hmac     : #{hxf @hmac}"
        puts ""
        list.each { |f| puts "#{" " * (26 - f.label.length)}#{f.label}: #{f}" }

        nil
      end

      private

      def _k
        @K ||= decrypt_key(@b1b2)
      end

      def _l
        @L ||= decrypt_key(@b3b4)
      end

      def decrypt_data(block)
        raise DecodeError.not_authenticated unless @stretch_key
        @tfd ||= Zweifische::Cipher256cbc.new(_k, @iv)
        @tfd.decrypt_update(block)
      end

      def decrypt_key(p)
        raise DecodeErrOr.not_authenticated unless @stretch_key
        @tfk ||= Zweifische::Cipher256ecb.new(@stretch_key)
        @tfk.decrypt(p)
      end

      def reset_keys
        @tfd = @tfk = @K = @L = nil
        reset_header
        reset_data
        reset_stretch_key
      end

      def reset_header
        @header = HeaderList.new
      end

      def reset_data
        @fields = FieldList.new
      end

      def reset_stretch_key
        @stretch_key = nil
        false
      end

      def stretch_key(str, iteration)
        @stretch_key = (1 + iteration).times.reduce(str + @salt) do |ac, _|
          OpenSSL::Digest::SHA256.digest(ac)
        end
      end

      def assert_eof(eof)
        return if eof.eql?(EOF)
        raise DecodeError.file_corrupt(self.class.name)
      end

      def assert_filetype(tag)
        return if tag.eql?(TAG)
        raise DecodeError.wrong_type(self.class.name)
      end
    end
  end
end
