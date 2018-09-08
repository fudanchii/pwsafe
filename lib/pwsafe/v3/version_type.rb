module Pwsafe
  module V3
    class VersionType < BytesType
      VERSION_MAP = {
        "\x00\x03" => "v3.01",
        "\x01\x03" => "v3.03",
        "\x02\x03" => "v3.09",
        "\x03\x03" => "v3.12",
        "\x04\x03" => "v3.13",
        "\x05\x03" => "v3.14",
        "\x06\x03" => "v3.19",
        "\x07\x03" => "v3.22",
        "\x08\x03" => "v3.25",
        "\x09\x03" => "v3.26",
        "\x0a\x03" => "v3.28",
        "\x0b\x03" => "v3.29",
        "\x0c\x03" => "v3.29Y",
        "\x0d\x03" => "v3.30",
        "\x0e\x03" => "v3.47",
      }

      def to_str
        VERSION_MAP[@data]
      end
    end
  end
end
