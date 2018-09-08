module Pwsafe
  module Utils
    def hxf(str)
      str.unpack("H*").first
    end

    def uint32(str)
      str
        .unpack("V")
        .first
        .to_i
    end
  end
end
