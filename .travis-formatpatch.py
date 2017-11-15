#!/usr/bin/python3

import sys
from xml.etree import ElementTree

def file_line_of_offset(file_object, offset, length):
    begin_offset = offset
    while begin_offset > 0:
        begin_offset -= 1
        file_object.seek(begin_offset)
        if file_object.read(1) in [b'\n', b'\r']:
            begin_offset += 1
            break
    end_offset = offset + length
    while True:
        file_object.seek(end_offset)
        if file_object.read(1) in [b'\n', b'\r', b'']:
            break
        end_offset += 1
    file_object.seek(begin_offset)
    line = file_object.read(end_offset - begin_offset)
    file_object.seek(0)
    line_no = len(file_object.readlines(begin_offset))
    return (offset - begin_offset, line_no, line)

def usage():
    print(sys.argv[0] + " [file]")

def main():
    if len(sys.argv) != 2:
        usage()
        exit(-1)
    file_path = sys.argv[1]
    ret = 0
    with open(file_path, 'rb') as file_object:
        try:
            for (_, elem) in ElementTree.iterparse(sys.stdin):
                if elem.tag == "replacement":
                    offset = int(elem.get('offset', 0))
                    length = int(elem.get('length', 0))
                    replace_text = (elem.text or '').encode()
                    offset_rel, line_no, line_orig = file_line_of_offset(
                        file_object, offset, length)
                    line_change = line_orig[0:offset_rel] + \
                            replace_text + \
                            line_orig[offset_rel+length:]
                    print("{}:{}".format(file_path, line_no))
                    print("\torig: {}".format(line_orig))
                    print("\trepl: {}".format(line_change))
                    ret = 1
        except ElementTree.ParseError as exception:
            ret = 1
            print("XML parse error:", exception, file=sys.stderr)
    exit(ret)

if __name__ == "__main__":
    main()
