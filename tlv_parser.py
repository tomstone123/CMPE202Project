#!/usr/bin/env python
"""
Pacifying Pylint and adding docstring for project
"""
import os
import copy

def value_convert(x_value):
    """
    This function attempt to decode the bytes value with ascii.
    If that's not possible then simply return the hex value
    :param x: The bytes input
    :return: The ascii or hex representation of the bytes
    """
    try:
        return x_value.decode("ascii")
    except UnicodeDecodeError:
        return x_value.hex()


def byteslist_to_int(byteslist):
    """
    This function takes a list of bytes and convert the value to a base 10 int
    :param byteslist: the list of bytes
    :return: integer of the list of bytes
    """
    holder = bytes()
    for value in byteslist:
        holder += value
    return int.from_bytes(holder, byteorder='big')


HEADER_TYPES = {
    1: "VERSION",
    2: "HEADERLENGTH",
    4: "SIGNERNAME",
    5: "SERIALNUMBER",
    6: "CANAME",
    8: "DIGESTALGO",
    12: "SIGNATURE",
    14: "FILENAME",
    15: "TIMESTAMP"
}

HEADER_TYPES_2 = {
    3: "SIGNERID",
    7: "SIGNATUREINFO",
    9: "SIGNATUREALGOINFO",
    10: "SIGNATUREALGO",
    11: "SIGNATUREMODULUS",
}

BODY = {
    1: "RECORDLENGTH",
    2: "DNSNAME",
    3: "SUBJECTNAME",
    4: "FUNCTION",
    5: "ISSUERNAME",
    6: "SERIAL NUMBER",
    7: "PUBLICKEY",
    8: "SIGNATURE",
    9: "CERTIFICATE",
    10: "IPADDRESS"
}

def parse_tlv(tlv_file):
    """
    This function take and parse a TLV file. Returning its header and body records
    :param tlv_file: The TLV file to parse
    :return: Print out of the TLV content
    """

    def process_value_body(data_dict, field):
        """
        This function process record body data
        :param data_dict: the data dictionary currently holding the data of the body
        :param field: the field type
        :return:
        """
        string1 = "test"

        if field == 1:
            nonlocal next_body
            nonlocal body_count
            body_length = byteslist_to_int(data_dict[field])
            next_body = body_length + bytes_index
            body_count += 1
            print("\nStart processing record body #{}".format(body_count))
            print("{:<6d}        {:<17s}        {:<5d}        {}".format(field, BODY[field]
                                                                         , 2, body_length))
        else:
            if field in BODY:
                if field in (6, 7, 8, 9, 10):
                    string1 = "Not Displayed"
                else:
                    string1 = "".join([value_convert(x) for x in data_dict[field]])

                print("{:<6d}        {:<17s}        {:<5d}        {}".format(field,
                                                                             BODY[field],
                                                                             len(data_dict[field]),
                                                                             string1))

    def process_value_header(data_dict, field):
        """
        This function process header data
        :param data_dict: the data dictionary currently holding the data of the body
        :param field: the field type
        :return:
        """
        if field == 1:
            ver_maj, ver_min = int.from_bytes(data_dict[field][0], byteorder="big"), int.from_bytes(
                data_dict[field][1], byteorder="big")
            print("{:<6d}        {:<17s}        {:<5d}        {}.{}".format(field,
                                                                            HEADER_TYPES[field],
                                                                            len(data_dict[field]),
                                                                            ver_maj, ver_min))
        elif field == 2:
            nonlocal header_length
            nonlocal next_body
            header_length = byteslist_to_int(data_dict[field])
            next_body = header_length + 1
            print("{:<6d}        {:<17s}        {:<5d}        {}".format(field,
                                                                         HEADER_TYPES[field],
                                                                         2,
                                                                         header_length))
        else:
            if field in HEADER_TYPES:

                if field in (6, 7, 8, 9, 10, 12):
                    string1 = "Not Displayed"
                else:
                    string1 = "".join([value_convert(x) for x in data_dict[field]])

                print("{:<6d}        {:<17s}        {:<5d}        {}".format(field,
                                                                             HEADER_TYPES[field],
                                                                             len(data_dict[field]),
                                                                             string1))
            elif field in HEADER_TYPES_2:
                print("{:<6d}        {:<17s}        {:<5d}        {}".format(field,
                                                                             HEADER_TYPES_2[field],
                                                                             2,
                                                                             byteslist_to_int(data_dict[field])))

    bm_type_header_no_data = copy.deepcopy(HEADER_TYPES_2)
    bm_type_header_with_data = copy.deepcopy(HEADER_TYPES)
    bm_type_body = copy.deepcopy(BODY)

    if os.path.isfile(tlv_file):
        file_size = os.path.getsize(tlv_file)
        print("This is a file. file size is: {} bytes".format(file_size))
        print("Starting to process the file")
        print("BYTEPOS       TAG                      LENGTH       VALUE")

        data_dict = {}

        with open(tlv_file, "rb") as file:
            bytes_read = file.read(1)
            header_length = file_size
            next_body = file_size
            body_count = 0
            bytes_index = 1

            field = ''
            length_count = 0
            length = 0
            length_holder = []
            while bytes_read != b"":
                # this boolean ensure that we only do 1 action per bytes read from the file
                work_done = False
                bytes_read_int = int.from_bytes(bytes_read, byteorder='big')

                # start processing the field value once we have the length
                if length > 0 and not work_done:
                    work_done = True
                    data_dict[field].append(bytes_read)
                    length -= 1
                    if length < 1:
                        if bytes_index >= header_length:
                            process_value_body(data_dict, field)
                        else:
                            process_value_header(data_dict, field)

                # start working on getting the field length
                if length_count > 0 and not work_done:
                    work_done = True
                    length_holder.append(bytes_read)
                    length_count -= 1
                    # field length of 2 bytes is captured.
                    # start processing the length bytes into int
                    if length_count < 1:
                        # this is one of the field type that contains just value
                        if field in bm_type_header_no_data and bytes_index < header_length:
                            data_dict[field] = copy.deepcopy(length_holder)
                            process_value_header(data_dict, field)
                            bm_type_header_no_data.pop(field)
                            length_holder.clear()
                        else:
                            length = byteslist_to_int(length_holder)
                            length_holder.clear()

                # process the header part of the file
                if bytes_read_int in bm_type_body and \
                   bytes_index >= header_length and \
                   not work_done:
                    # length is 2 bytes. set length counter to 2.
                    # initiating type list to prep for incoming data
                    length_count = 2
                    field = bytes_read_int
                    data_dict[field] = []

                    # field type found, removing found type from type list
                    # if it's one that has no data content
                    bm_type_body.pop(field)
                elif (
                        bytes_read_int in bm_type_header_with_data \
                                or bytes_read_int in bm_type_header_no_data) \
                                and not work_done:
                    # length is 2 bytes. set length counter to 2
                    # initiating type list to prep for incoming data
                    length_count = 2
                    field = bytes_read_int
                    data_dict[field] = []

                    # field type found, removing found type from type list
                    # if it's one that has no data content
                    if bytes_read_int in bm_type_header_with_data:
                        bm_type_header_with_data.pop(field)

                bytes_read = file.read(1)
                bytes_index += 1

                if bytes_index >= header_length:
                    bm_type_header_no_data.clear()
                    bm_type_header_with_data.clear()

                if bytes_index >= next_body:
                    bm_type_body = copy.deepcopy(BODY)


if __name__ == "__main__":
    #parse_tlv('D:\School\CMPE 202\SCFProgram\SCFFile.tlv')
    parse_tlv('./SCFFile.tlv')
