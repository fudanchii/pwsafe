module Pwsafe
  module V3
    class EndType < BytesType
      def to_str
        "end-of-entry"
      end
    end

    HeaderTagClass = {
      0x00 => { type: VersionType, name: "Version" },
      0x01 => { type: UUIDType,    name: "UUID" },
      0x02 => { type: NonDefaultPreferenceType,
                                   name: "Non-default Preference" },
      0x03 => { type: TextType,    name: "Tree Display Status" },
      0x04 => { type: TimeType,    name: "Last Save Timestamp" },
      0x05 => { type: TextType,    name: "Who performed last save" },
      0x06 => { type: TextType,    name: "What performed last save" },
      0x07 => { type: TextType,    name: "Last saved by user" },
      0x08 => { type: TextType,    name: "Last saved on host" },
      0x09 => { type: TextType,    name: "Database Name" },
      0x0a => { type: TextType,    name: "Database Description" },
      0x0b => { type: TextType,    name: "Database Filters" },
      0x0c => { }, # reserved
      0x0d => { }, # reserved
      0x0e => { }, # reserved
      0x0f => { type: TextType,    name: "Recently Used Entries" },
      0x10 => { type: TextType,    name: "Named Password Policies" },
      0x11 => { type: TextType,    name: "Empty Groups" },
      0x12 => { type: TextType,    name: "Yubico" },
      0x13 => { type: TimeType,    name: "Last master password change" },
      0xff => { type: EndType,     name: "End of entry" }
    }

    DataTagClass = {
      0x01 => { type: UUIDType, name: "UUID" },
      0x02 => { type: TextType, name: "Group" },
      0x03 => { type: TextType, name: "Title" },
      0x04 => { type: TextType, name: "Username" },
      0x05 => { type: TextType, name: "Notes" },
      0x06 => { type: TextType, name: "Password" },
      0x07 => { type: TimeType, name: "Creation Time" },
      0x08 => { type: TimeType, name: "Password Modification Time" },
      0x09 => { type: TimeType, name: "Last Access Time" },
      0x0a => { type: TimeType, name: "Password Expiry Time" },
      0x0b => { }, # reserved
      0x0c => { type: TimeType, name: "Last Modification Time" },
      0x0d => { type: TextType, name: "URL" },
      0x0e => { type: TextType, name: "Autotype" },
      0x0f => { type: TextType, name: "Password History" },
      0x10 => { type: TextType, name: "Password Policy" },
      0x11 => { type: Uint32Type,
                                name: "Password Expiry Interval" },
      0x12 => { type: TextType, name: "Run Command" },
      0x13 => { type: BytesType,
                                name: "Double-Click Action" },
      0x14 => { type: TextType, name: "Email Address" },
      0x15 => { type: BytesType,
                                name: "Protected Entry" },
      0x16 => { type: TextType, name: "Own Symbols for Password" },
      0x17 => { type: BytesType,
                                name: "Shift-Double-CLick Action" },
      0x18 => { type: TextType, name: "Password Policy Name" },
      0x19 => { type: BytesType,
                                name: "Entry Keyboard Shortcut" },
      0x1a => { type: UUIDType, name: "# Reserved" }, # reserved
      0x1b => { type: BytesType,
                                name: "Two-Factor Key" },
      0x1c => { type: TextType, name: "Credit Card Number" },
      0x1d => { type: TextType, name: "Credit Card Expiration" },
      0x1e => { type: TextType, name: "Credit Card Verif. Value" },
      0x1f => { type: TextType, name: "Credit Card Pin" },
      0x20 => { type: TextType, name: "QR Code" },
      0xdf => { }, # unknown (testing)
      # 0xe0 - 0xfe may be implemented later in user code
      0xff => { type: EndType,     name: "End of entry" }
    }
  end
end
