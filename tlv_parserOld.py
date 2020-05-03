import sys
import os
import copy
from parser_util import byteslist_to_int, value_convert


def parse_tlv(tlv_file):
    """
    This function take and parse a TLV file. Returning its header and body records
    :param tlv_file: The TLV file to parse
    :return: Print out of the TLV content
    """
    header_types = {
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

    header_types_2 = {
        3: "SIGNERID",
        7: "SIGNATUREINFO",
        9: "SIGNATUREALGOINFO",
        10: "SIGNATUREALGO",
        11: "SIGNATUREMODULUS",
    }

    body_types = {
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

    def process_value_body(data_dict, field_type):
        """
        This function process record body data
        :param data_dict: the data dictionary currently holding the data of the body
        :param field_type: the field type
        :return:
        """
        String1 = "test"
        
        if field_type == 1:

            #print("Tommy || {}".format(field_type))

            if field_type == 6 or field_type == 7 or field_type == 8 or field_type == 9 or field_type == 10:
                String1 = "Not Displayed"
            else:
                String1 = "".join([value_convert(x) for x in data_dict[field_type]])
                   
            nonlocal next_body
            nonlocal body_count
            body_length = byteslist_to_int(data_dict[field_type])
            next_body = body_length + bytes_index
            body_count += 1
            print("\nStart processing record body #{}".format(body_count))
            print("{}    --    {}    --    {}    --    {}".format(field_type, body_types[field_type], 2, body_length))
        else:
            if field_type in body_types:
                #print("Tommy || {}".format(field_type))
                
                if field_type == 6 or field_type == 7 or field_type == 8 or field_type == 9 or field_type == 10:
                   String1 = "Not Displayed"
                else:
                    String1 = "".join([value_convert(x) for x in data_dict[field_type]])
                   
                print("{}    --    {}    --    {}    --    {}".format(field_type, body_types[field_type], len(data_dict[field_type]), String1))

    def process_value_header(data_dict, field_type):
        """
        This function process header data
        :param data_dict: the data dictionary currently holding the data of the body
        :param field_type: the field type
        :return:
        """
        if field_type == 1:
            ver_maj, ver_min = int.from_bytes(data_dict[field_type][0], byteorder="big"), int.from_bytes(
                data_dict[field_type][1], byteorder="big")
            print("{}    --    {}    --    {}    --    {}.{}".format(field_type, header_types[field_type],
                                                               len(data_dict[field_type]),
                                                               ver_maj, ver_min))
        elif field_type == 2:
            nonlocal header_length
            nonlocal next_body
            header_length = byteslist_to_int(data_dict[field_type])
            next_body = header_length + 1
            print("{}    --    {}    --    {}    --    {}".format(field_type, header_types[field_type], 2, header_length))
        else:
            if field_type in header_types:
                print("{}    --    {}    --    {}    --    {}".format(field_type, header_types[field_type],
                                                                len(data_dict[field_type]),
                                                                "".join(
                                                                    [value_convert(x) for x in data_dict[field_type]])))
            elif field_type in header_types_2:
                print("{}    --    {}    --    {}    --    {}".format(field_type, header_types_2[field_type], 2,
                                                                byteslist_to_int(data_dict[field_type])))

    bm_type_header_no_data = copy.deepcopy(header_types_2)
    bm_type_header_with_data = copy.deepcopy(header_types)
    bm_type_body = copy.deepcopy(body_types)

    if os.path.isfile(tlv_file):
        file_size = os.path.getsize(tlv_file)
        print("This is a file. file size is: {} bytes".format(file_size))
        print("Starting to process the file")
        print("BYTEPOS   --   TAG   --   LENGTH   --   VALUE")

        data_dict = {}

        with open(tlv_file, "rb") as file:
            bytes_read = file.read(1)
            header_length = file_size
            next_body = file_size
            body_count = 0
            bytes_index = 1

            field_type = ''
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
                    data_dict[field_type].append(bytes_read)
                    length -= 1
                    if length < 1:
                        if bytes_index >= header_length:
                            process_value_body(data_dict, field_type)
                        else:
                            process_value_header(data_dict, field_type)

                # start working on getting the field length
                if length_count > 0 and not work_done:
                    work_done = True
                    length_holder.append(bytes_read)
                    length_count -= 1
                    # field length of 2 bytes is captured. start processing the length bytes into int
                    if length_count < 1:
                        # this is one of the field type that contains just value
                        if field_type in bm_type_header_no_data and bytes_index < header_length:
                            data_dict[field_type] = copy.deepcopy(length_holder)
                            process_value_header(data_dict, field_type)
                            bm_type_header_no_data.pop(field_type)
                            length_holder.clear()
                        else:
                            length = byteslist_to_int(length_holder)
                            length_holder.clear()

                # process the header part of the file
                if bytes_read_int in bm_type_body and bytes_index >= header_length and not work_done:
                    # length is 2 bytes. set length counter to 2. initiating type list to prep for incoming data
                    length_count = 2
                    field_type = bytes_read_int
                    data_dict[field_type] = []

                    # field type found, removing found type from type list...if it's one that has no data content
                    bm_type_body.pop(field_type)
                elif (
                        bytes_read_int in bm_type_header_with_data or bytes_read_int in bm_type_header_no_data) \
                        and not work_done:
                    # length is 2 bytes. set length counter to 2. initiating type list to prep for incoming data
                    length_count = 2
                    field_type = bytes_read_int
                    data_dict[field_type] = []

                    # field type found, removing found type from type list...if it's one that has no data content
                    if bytes_read_int in bm_type_header_with_data:
                        bm_type_header_with_data.pop(field_type)

                bytes_read = file.read(1)
                bytes_index += 1

                if bytes_index >= header_length:
                    bm_type_header_no_data.clear()
                    bm_type_header_with_data.clear()

                if bytes_index >= next_body:
                    bm_type_body = copy.deepcopy(body_types)


if __name__ == "__main__":
    parse_tlv('D:\School\CMPE 202\SCFProgram\SCFFile.tlv')
