require "openssl"
require "zweifische"

class Pwsafe::V3::Decoder
  def initialize(filename = DEFAULT_PSAFE_FILE)
    File.open(filename, "rb") do |f|
      assert_filetype(f.read(4))

      @salt = f.read(32) # 256 bit
      @iteration = unpack_uint32(f)
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

  def password_valid?(password)
    reset_keys
    OpenSSL::Digest::SHA256
      .digest(stretch_key(password, @iteration))
      .eql?(@p_hash) || reset_keys
  end

  def debug(password)
    puts "password : #{password_valid?(password).inspect}"
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
  end

  private

  def _k
    @K ||= decrypt_key(@b1b2)
  end

  def _l
    @L ||= decrypt_key(@b3b4)
  end

  def decrypt_key(p)
    raise DecodeError.not_authenticated unless @stretch_key
    @tfk ||= Zweifische::Cipher256ecb.new(@stretch_key)
    @tfk.decrypt(p)
  end

  def reset_keys
    @tfk = @K = @L = nil
    reset_stretch_key
  end

  def reset_stretch_key
    @stretch_key = nil
    false
  end

  def hxf(str)
    str.unpack("H*").first
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

  def unpack_uint32(file)
    file
      .read(4)
      .unpack("V")
      .first
      .to_i
  end
end
