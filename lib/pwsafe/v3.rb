module Pwsafe
  module V3
    TAG = "PWS3"
    EOF = "PWS3-EOFPWS3-EOF"
    DEFAULT_PSAFE_FILE = "pwsafe.psafe3"
  end
end

require "pwsafe/v3/bytes_type"
require "pwsafe/v3/version_type"
require "pwsafe/v3/text_type"
require "pwsafe/v3/time_type"
require "pwsafe/v3/uuid_type"
require "pwsafe/v3/uint32_type"
require "pwsafe/v3/non_default_preference_type"

require "pwsafe/v3/tag_class"
require "pwsafe/v3/field_list"
require "pwsafe/v3/header_list"
require "pwsafe/v3/decoder"
