import construct as c


class v3_1:

    def __init__(self):
        self.signature = 0xc0dec0df  # сигнатура для проверки дешифровки
        self.offset = 0xd0  # оффсет из самого начала функции расшифровки где xmm
        self.header = c.Struct(
                                "Signature" / c.Int32ul,
                                "ImageBase" / c.Int64ul,
                                "AddressOfEntryPoint" / c.Int64ul,
                                "BindSectionOffset" / c.Int32ul,
                                "Unknown0000" / c.Int32ul,
                                "OriginalEntryPoint" / c.Int64ul,
                                "Unknown0001" / c.Int32ul,
                                "PayloadSize" / c.Int32ul,
                                "DRMPDllOffset" / c.Int32ul,
                                "DRMPDllSize" / c.Int32ul,
                                "SteamAppId" / c.Int32ul,
                                "Flags" / c.Int32ul,
                                "BindSectionVirtualSize" / c.Int32ul,
                                "Unknown0002" / c.Int32ul,
                                "CodeSectionVirtualAddress" / c.Int64ul,
                                "CodeSectionRawSize" / c.Int64ul,
                                "AES_KEY" / c.Array(0x20, c.Int8ul),
                                "AES_IV" / c.Array(0x10, c.Int8ul),
                                "CodeSectionStolenData" / c.Array(0x10, c.Int8ul),
                                "EncryptionKeys" / c.Array(0x4, c.Int32ul),
                        )


class v3_0:

    def __init__(self):
        self.signature = 0xc0dec0de
        self.offset = 0xc0
        self.header = c.Struct(
                                "Signature" / c.Int32ul,
                                "ImageBase" / c.Int64ul,
                                "AddressOfEntryPoint" / c.Int32ul,
                                "BindSectionOffset" / c.Int32ul,
                                "Unknown0000" / c.Int32ul,
                                "OriginalEntryPoint" / c.Int32ul,
                                "Unknown0001" / c.Int32ul,
                                "PayloadSize" / c.Int32ul,
                                "DRMPDllOffset" / c.Int32ul,
                                "DRMPDllSize" / c.Int32ul,
                                "SteamAppId" / c.Int32ul,
                                "Flags" / c.Int32ul,
                                "BindSectionVirtualSize" / c.Int32ul,
                                "Unknown0002" / c.Int32ul,
                                "CodeSectionVirtualAddress" / c.Int32ul,
                                "CodeSectionRawSize" / c.Int32ul,
                                "AES_KEY" / c.Array(0x20, c.Int8ul),
                                "AES_IV" / c.Array(0x10, c.Int8ul),
                                "CodeSectionStolenData" / c.Array(0x10, c.Int8ul),
                                "EncryptionKeys" / c.Array(0x4, c.Int32ul),
                        )
