from bitarray import bitarray
import csv
import math
import sys
import struct

def encode_byte_map_to_256bit(byte_map): #useful to store more than 32 dictionary values in no more than 32bytes

    encoded = bitarray(256)
    encoded.setall(0)  # Initialize all bits to 0

    for value in byte_map:

        if 0 <= value <= 255:
            encoded[value] = 1

    byte_array = encoded.tobytes()

    return byte_array

def decode_256bit_from_bytes(encoded_bytes):

    # Convert the byte array back to a bitarray
    encoded = bitarray()
    encoded.frombytes(bytearray(encoded_bytes))

    # Reconstruct the original list of integers
    byte_map = [i for i in range(256) if encoded[i]]

    return byte_map

def list_to_string(lst):

    return "[" + ", ".join(
        list_to_string(sublist) if isinstance(sublist, list) else str(sublist)
        for sublist in lst
    ) + "]"

def write_to_txt(output_path, compressed_list):

    with open(output_path, 'w') as f:
        for sublist in compressed_list:
            f.write(list_to_string(sublist) + '\n')

def sort_by_frequency_and_filter(item_list):

    # Count the unique items
    counts = count_unique_items(item_list)

    # Filter and sort the items by frequency (only items with frequency > 1)
    filtered_sorted_items = sorted(
        (item for item in counts.items() if item[1] > 1), 
        key=lambda x: x[1], 
        reverse=True
    )

    # Convert tuples back to lists
    sorted_lists = [list(item[0]) for item in filtered_sorted_items]

    return sorted_lists

def count_unique_items(item_list):

    unique_counts = {}

    for item in item_list:

        # Convert the unhashable item (e.g., list or dict) to a hashable type (e.g., tuple or frozenset)
        hashable_item = tuple(item) if isinstance(item, list) else frozenset(item.items()) if isinstance(item, dict) else item

        if hashable_item in unique_counts:
            unique_counts[hashable_item] += 1
        else:
            unique_counts[hashable_item] = 1

    # Return the count of unique items
    return unique_counts

def handle_bit_reduced_data(bytestream, idx, instruction): #this returns the bit reduced data to its original state
    
    if 11 <= instruction <= 17: #1 to 7 bit redux for a 2 byte long length of bytes
        length = struct.unpack(">H", bytes(bytestream[idx:idx+2]))[0]
        idx += 2
        instruction -= 10 #instruction goes back to 1 to 7 bit redux       
   
    else: #1 to 7 bit redux for a 1 byte long length of bytes
        length = bytestream[idx]
        idx += 1
    
    map_length = min(2**instruction,32) #if it's more than 32 encode the values in a 256bit value

    if 6 <= instruction <=7 or 16 <= instruction <=17: #signal when to use 256bit encoding for the map
        byte_map = decode_256bit_from_bytes(bytestream[idx:idx+32])

    else:
        byte_map = {}
        premature_end_detected = False

        for i in range(map_length):

            if i < len(bytestream[idx:idx+map_length]) - 1 and bytestream[idx+i] == bytestream[idx+i+1]: #if the last 2 values found before the map max length are the same then the map isn't as long as max length and we truncate it, saving bytes
                map_length = i + 1
                premature_end_detected = True
                break

            byte_map[i] = bytestream[idx+i]
    
        if premature_end_detected:
            idx += 1 #push idx 1 value up if the map gets truncated because the final double value is ignored from now on.
            byte_map[map_length-1] = bytestream[idx+map_length-1]
            
    idx += min(len(byte_map),32) #idx goes up either the length of the map or 32 if using 256bit encoding for it
    
    bit_data_length = (length * instruction + 7) // 8 #how many bytes will be decoded from the bit reduced stream
    bit_data = ''.join(format(b, '08b') for b in bytestream[idx:idx+bit_data_length]) #create the 0s and 1s stream
    decompressed = []

    for i in range(0, length * instruction, instruction): #loop through the bits assuming the instruction is the length of the reduced bytes

        if i + instruction > len(bit_data): #no more bits to decode
            break

        key = int(bit_data[i:i+instruction], 2) #find the key for the original value
        decompressed.append(byte_map[key]) #add the original value

    idx += bit_data_length #increase by bit_data_length because that's the real amount of bytes analyzed from the compressed file, not length

    return idx, decompressed, byte_map

def decompress(bytes_read,file_path): #the main decompression loop

    with open(file_path+'.raz', 'rb') as f: #testing function, compressed file path will be given by argument in the future
        bytestream = f.read()

    
    # Convert bytes to their numerical values
    byte_values = list(bytestream)

    # Write the list of byte values to a new file
    with open('output_fil22e.txt', 'w') as output_file:
        output_file.write(str(byte_values))

    decompressed = []
    idx = 0
    sequence = bytearray(b'%RAZv') + bytearray([0, 1]) + bytearray(b'x') #the magic number I expect at the beginning of a .raz file. will need to handle this dynamically for different dictionaries and recursion in the future

    while idx < len(bytestream) - len(sequence) + 1: #magic number check
        if bytestream[idx:idx+len(sequence)] == sequence:
            break
        if idx > len(sequence):
            print('This is''nt a valid RAZ file!')
            return
        idx += 1

    idx += len(sequence)

    instructions = []
    byte_maps = []

    while idx < len(bytestream):

        if idx > 40000: #stupid check, gotta learn how to profile code
            yoyo =270

        instruction = bytestream[idx]

        if instruction == 10: #append next one byte
            idx += 1
            decompressed.append(bytestream[idx])
            idx += 1

        elif instruction == 0: #extend by next bytes (1 byte long length)
            idx += 1
            length = bytestream[idx]
            decompressed.extend(bytestream[idx+1:idx+1+length])
            idx += length + 1

        elif instruction == 21: #extend by next bytes (2 bytes long length)
            idx += 1
            length = struct.unpack(">H", bytestream[idx:idx+2])[0]
            decompressed.extend(bytestream[idx+2:idx+2+length])
            idx += length + 2

        elif 1 <= instruction <= 7 or 11 <= instruction <= 17: #extend by the 1-7 bit unreduced bytes
            idx, decompressed_data, byte_map = handle_bit_reduced_data(bytestream, idx+1, instruction)
            decompressed.extend(decompressed_data)
            instructions.append(instruction) #save instruction and byte map for future reference. gotta make sure to revolve the map so that it can be 256 long max
            byte_maps.append(byte_map)

        elif instruction == 9 or instruction == 19: #use a previously stored instruction and map, saving the corresponding bytes

            idx += 1
            go_back = bytestream[idx] #how many positions back in the saved instructions list do I need to go?
            referenced_instruction = instructions[(len(instructions)-1)-go_back] #this maybe isn't the best way to calculate it. maybe it's better to have go_back be larger by 1

            if referenced_instruction > 10 and instruction < 10: #these 2 checks make sure that the length of bytes to decode is right, regardless if the instruction was for long or short bytes
                instruction = referenced_instruction - 10

            elif referenced_instruction < 10 and instruction > 10:
                instruction = referenced_instruction + 10

            else:
                instruction = referenced_instruction

            byte_map = byte_maps[(len(byte_maps)-1)-bytestream[idx]]
            idx += 1

            new_bytestream = []
            new_bytestream.append(bytestream[idx])

            if instruction > 10:
                new_bytestream.append(bytestream[idx+1]) #how many bytes are bit reduced here?

            byte_map_to_add = []

            for key in byte_map:
                byte_map_to_add.append(byte_map[key]) #rebuild the map

            if len(byte_map_to_add)>32: #if it's longer than 32 256bit encode it before passing it to the handler
                byte_map_to_add = encode_byte_map_to_256bit(byte_map_to_add)

            new_bytestream.extend(byte_map_to_add)

            if instruction > 10: #this makes sure the bytestream_limit calculation is based on the bit reduction number and not the instruction that may be different than the actual reduction number
                length = struct.unpack(">H", bytes(bytestream[idx:idx+2]))[0]
                bit_length = instruction - 10                
                bytestream_limit = ((length * bit_length + 7) // 8) + idx + 2

                for bytez in bytestream[idx+2:bytestream_limit]: #if the length takes 2 bytes to express don't add 1 to idx, or the code shall perish in darkness!
                    new_bytestream.append(bytez)

            else:
                bytestream_limit = ((bytestream[idx] * instruction + 7) // 8) + idx + 1 #it's vital to always consider that data at this point is still packed, can't rely on the byte length instruction, it needs to be multiplied by the multiplier

                for bytez in bytestream[idx+1:bytestream_limit]: #add the bytes to unreduce (start from idx+1 or pay the price of your foolishness!)
                    new_bytestream.append(bytez)

            nidx, decompressed_data, byte_map = handle_bit_reduced_data(new_bytestream, 0, instruction) #handle the data and return nidx, an idx that starts from 0
            
            idx += nidx - len(byte_map) #-len(byte_map) coz guess what THERE's NO BYTE MAP HERE!!!

            decompressed.extend(decompressed_data)

        else: #ridiculous function to delete

            print('trouble at idx: '+str(idx)+'\tinstruction: '+str(instruction))
            user_input = input("Wanna go up or down? (Type 'exit' to quit) ").lower()

            # Check the user's input and act accordingly
            if user_input == "u":
                idx += 1

            elif user_input == "d":
                idx -= 1

            elif user_input == "exit":
                print("Exiting the program.")
                break

            else:
                print("Invalid input. Please type 'up', 'down', or 'exit'.")
        
    if idx < len(bytestream): #if I decompressed everything but I find more bytes, I just copy them
        decompressed.extend(bytestream[idx:])

    with open('decompressed_'+file_path, 'wb') as f:
        f.write(bytearray(decompressed))
    
    print('original: '+str(len(decompressed))+ ' compressed: '+str(len(bytestream))+' ratio: '+str(len(bytestream)/len(decompressed)))

def compress_final(final_compressed,file_path):

    bytestream = bytearray(b'%RAZv') + bytearray([0, 1]) + bytearray(b'x') #magic number
    past_instructions = []
    past_byte_maps = []

    for lst in final_compressed: #write the compressed file according to instructions
        instruction = lst[0]
        data = lst[1:]

        if instruction == 10: #next byte unaffected
            bytestream.append(10)
            bytestream.append(data[0])

        elif instruction == 0: #next x bytes unaffected
            length = len(data)

            if length < 256:
                bytestream.append(0)
                bytestream.append(length)
                bytestream.extend(data)

            elif len(data) < 65536:
                bytestream.append(21)
                bytestream.extend(struct.pack(">H", length))
                bytestream.extend(data)

            else: #divide into chunks that are smaller than 65536 and bigger than 256 to avoid handling chunks bigger than 64KB
                total_length = len(data)
                chunk_size = 65535

                while total_length / (total_length // chunk_size) <= 255:
                    chunk_size -= 1

                for i in range(0, total_length, chunk_size):
                    chunk = data[i:i + chunk_size]
                    bytestream.extend([21] + list(struct.pack(">H", len(chunk))))
                    bytestream.extend(chunk)


        elif 1 <= instruction <= 7: #bit reduce this data            
            unique_bytes = sorted(list(set(data)))
            original_instruction = instruction
            max_unique_values = min(2 ** instruction,32)
            go_back = -1

            for ii in range(len(past_instructions),0,-1): #check past instructions and maps to see if we can reduce the instruction to 9

                if (past_instructions[ii-1] == instruction or past_instructions[ii-1] == instruction + 10 or past_instructions[ii-1] == instruction - 10) and past_byte_maps[ii-1] == unique_bytes:
                    go_back = len(past_instructions) - ii

                    if go_back < 256: #storing go_back in 1 byte 255 is the max value I will go back (for the moment)
                        instruction = 9
                        break

                    else:
                        go_back = -1 #no need to go back

            if go_back == -1: #normal bit reduction of bytes

                if len(data) < 256:
                    bytestream.append(instruction)
                    bytestream.append(len(data))

                elif len(data) < 65536:
                    bytestream.append(instruction+10)
                    bytestream.extend(list(struct.pack(">H", len(data))))

                else:                
                    print('omg!') #omg isn't a very good way to handle this case

                if len(unique_bytes) > 32: #encode in 256bits byte maps larger than 32
                    unique_bytes_packed = encode_byte_map_to_256bit(unique_bytes)
                    bytestream.extend(unique_bytes_packed)

                elif len(unique_bytes) < max_unique_values: #double last map value to truncate it before max length
                    unique_bytes.append(unique_bytes[-1])
                    bytestream.extend(unique_bytes)

                else:
                    bytestream.extend(unique_bytes)
                
                past_instructions.append(instruction)
                past_byte_maps.append(unique_bytes)

            else: #if instruction is already present

                if len(data) < 256:
                    bytestream.append(instruction)
                    bytestream.append(go_back)
                    bytestream.append(len(data))

                elif len(data) < 65536:
                    instruction += 10
                    bytestream.append(instruction)
                    bytestream.append(go_back)
                    bytestream.extend(list(struct.pack(">H", len(data))))

                else:                
                    print('omg!') #bah


                if original_instruction < 10: #return the right instruction to encode data
                    instruction = original_instruction

                else:
                    instruction = original_instruction - 10

            byte_map = {}

            for idx, byte in enumerate(unique_bytes): #build byte map
                byte_map[byte] = idx

            if len(unique_bytes) > 2 and unique_bytes[-1] == unique_bytes[-2]: #handle truncated byte map
                byte_map[unique_bytes[-2]] = len(unique_bytes) - 2
            
            packed_data = []
            
            for byte in data: #write bit reduced data after mapping
                value_to_write = byte_map[byte]
                packed_data.extend(format(value_to_write, f'0{instruction}b'))

            while len(packed_data) % 8 != 0: #append 0 bits if value ends before end of byte
                packed_data.append('0')

            for i in range(0, len(packed_data), 8): #add packed data to the bytestream
                bytestream.append(int("".join(packed_data[i:i+8]), 2))

    with open(file_path+'.raz', 'wb') as f:
        f.write(bytestream)
        
length_thresholds = {1: 11, 2: 15, 3: 24, 4: 43, 5: 81, 6: 159, 7: 319}
unique_byte_thresholds = {1: 2, 2: 4, 3: 8, 4: 16, 5: 32, 6: 64, 7: 128}    
multipliers = {1: 0.125, 2: 0.25, 3: 0.375, 4: 0.5, 5: 0.625, 6: 0.75, 7: 0.875}

def calculate_scores(bytes_list, reduction): #scoring can ignore thresholds if keep track of all instructions and maps in the method

    row = []
    for start_pos in range(len(bytes_list)):
    
        if isinstance(bytes_list[start_pos], list): #if it's a list it's already compressed. THIS WILL BE THE PART WHERE THE 9 INSTRUCTION WILL BE USED TO COMPRESS BACKGROUND DATA
            row.append(0)
            continue
    
        max_length = 0
        unique_bytes = set()
    
        for end_pos in range(start_pos, min(len(bytes_list),start_pos+65535)): 
    
            if isinstance(bytes_list[end_pos], list):
                break
    
            unique_bytes.add(bytes_list[end_pos])
    
            if len(unique_bytes) > unique_byte_thresholds[reduction]:
                break
    
            max_length += 1
        
        if max_length >= length_thresholds[reduction]:
            row.append(max_length) #is max length the best scoring possible?
    
        else:
            row.append(0)
    
    return row

def bit_reduction(less_bit_compressed, bits):

    more_bit_scores = calculate_scores(less_bit_compressed, bits)

    to_append = []
    more_bit_compressed = []
    overhead = 0
    allscore = 0
    i = 0

    while i < len(less_bit_compressed):

        score = more_bit_scores[i]

        if score>0:
            overhead += 2 + min(2**bits,32)
            allscore += score

            if isinstance(less_bit_compressed[i], list):
                sublist = less_bit_compressed[i]
                more_bit_compressed.append(sublist[:score])
                more_bit_compressed.extend(sublist[score:])

            else:
                more_bit_compressed.append( [bits] + list(less_bit_compressed[i:i+score]))
                to_append = []
                i += score - 1

        else:
            more_bit_compressed.append(less_bit_compressed[i])

        i += 1

    print(str(bits)+' bits done!\tOverhead: '+str(overhead)+'\t\tScore: '+str(allscore)+'\t\tExpected savings: '+str(allscore-overhead-int(allscore*(.125*bits))))

    return more_bit_compressed

def mark_uncompressed(data):

    marked_data = []
    instructionsets = []
    current_marked_sublist = []

    for item in data:

        if not isinstance(item, list):
            current_marked_sublist.append(item)

        else:
            instructionsets.append(sorted(set(item)))

            if current_marked_sublist:
                prefix = [10] if len(current_marked_sublist) == 1 else [0]
                marked_data.append(prefix + current_marked_sublist)
                current_marked_sublist = []

            if isinstance(item, list):
                marked_data.append(item)

            else:
                current_marked_sublist.append(item)

    if current_marked_sublist:
        prefix = [10] if len(current_marked_sublist) == 1 else [0]
        marked_data.append(prefix + current_marked_sublist)

    print(len(instructionsets))

    print(len(sort_by_frequency_and_filter(instructionsets)))

    return marked_data

def bit_reduction_feasibility(file_path):

    with open(file_path, 'rb') as f:
        bytes_read = f.read()

    one_bit_compressed = bit_reduction(bytes_read,1)

    two_bit_compressed = bit_reduction(one_bit_compressed,2)

    three_bit_compressed = bit_reduction(two_bit_compressed,3)

    four_bit_compressed = bit_reduction(three_bit_compressed, 4)

    five_bit_compressed = bit_reduction(four_bit_compressed, 5)

    six_bit_compressed = bit_reduction(five_bit_compressed, 6)

    seven_bit_compressed = bit_reduction(six_bit_compressed, 7)

    final_compressed = mark_uncompressed(seven_bit_compressed)
    
    write_to_txt('compressed_output.txt', final_compressed)
    compress_final(final_compressed,file_path)
    decompress(bytes_read,file_path)

def main():

    if len(sys.argv) != 2:
        print("Usage: raz.py <file_path>")
        file_path = 'ANGELLO.mp3'

    else:
        file_path = sys.argv[1]

    bit_reduction_feasibility(file_path)

if __name__ == "__main__":
    main()
