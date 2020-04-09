import util
import steam_header
import lief
import sys

filename = None
steam_h = None
binary = None


def parse_headers(header_size):
    address = binary.entrypoint - header_size
    size = binary.entrypoint - address
    content = binary.get_content_from_virtual_address(address, size)

    data, key = util.steam_xor(bytes(content))
    s_header = steam_h.header.parse(data)

    if s_header["Signature"] == steam_h.signature:
        return s_header, key
    print("error on parsing headers")
    exit(1)


def unpack_drmp(header):
    address = binary.entrypoint - header["BindSectionOffset"] + header["DRMPDllOffset"]
    size = header["DRMPDllSize"]
    content = binary.get_content_from_virtual_address(address, size)

    buff = util.drmp_decrypt(bytes(content), header["EncryptionKeys"])
    with open("SteamDRMP.so", "wb") as f:
        f.write(buff)


def decrypt_paylad(header, key):
    address = binary.entrypoint - header["BindSectionOffset"]
    size = (header["PayloadSize"] + 0x0F) & 0xFFFFFFF0
    content = binary.get_content_from_virtual_address(address, size)

    data, key = util.steam_xor(bytes(content), key)
    with open(filename + ".payload", "w") as f:
        f.write(str(data))


def decrypt_code(header):
    if header["Flags"] & 0x4 != 0x4:  # если не зашифрованно, то и расшифровывать не нужно
        buff = b""
        section = binary.section_from_virtual_address(header["CodeSectionVirtualAddress"] + header["ImageBase"])

        for i in header["CodeSectionStolenData"]:
            buff += i.to_bytes(1, byteorder="little")

        buff += bytes(section.content[:header["CodeSectionRawSize"]])
        section.content = util.decrypt_code(buff, header["AES_KEY"], header["AES_IV"])

    binary.header.entrypoint = header["OriginalEntryPoint"] + header["ImageBase"]
    binary.write(filename+".crk")


def parse_arguments_and_init_globals():
    global filename
    global binary
    global steam_h

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage:", sys.argv[0], "filename stub_ver \nstub_ver can be 3_1 or 3_0 and 3_1 by default")
        exit()

    filename = sys.argv[1]
    binary = lief.parse(filename)

    if len(sys.argv) == 3 and sys.argv[2] == "3_0":
        steam_h = steam_header.v3_0()
    else:
        steam_h = steam_header.v3_1()


def main():
    parse_arguments_and_init_globals()
    header, key = parse_headers(steam_h.offset)  # парсинг заголовков стима

#    decrypt_paylad(header, key)  # просто посмотреть, что там # ничего интересного

#    unpack_drmp(header)  # распаковка библиотеки защиты от дебага

    decrypt_code(header)  # собственно декрипт и перезапись кода игры


main()
