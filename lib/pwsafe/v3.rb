module Pwsafe
  module V3
    TAG = "PWS3"
    EOF = "PWS3-EOFPWS3-EOF"
    DEFAULT_PSAFE_FILE = "pwsafe.psafe3"
  end
end

require "pwsafe/v3/decoder"
