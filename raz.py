from bitarray import bitarray
import gc
from multiprocessing import Pool, cpu_count
import numpy as np
import os
import psutil
import struct
import sys
import time

def get_memory_usage():
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    return mem_info.rss  #in bytes

def format_bytes(size):
    #converts bytes to a human-readable format (KB, MB, GB)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024

def format_time(time):
    """Format elapsed time to hh:mm:ss.ff"""
    hours = int(time // 3600)
    minutes = int((time % 3600) // 60)
    seconds = time % 60
    return f"{hours:02}:{minutes:02}:{seconds:06.3f}"

def print_analysis_info(algo_str, overhead, allscore, expected_savings):
    overhead_str = format_bytes(overhead)
    allscore_str = format_bytes(allscore)
    expected_savings_str = format_bytes(expected_savings)

    print(f"\r{algo_str:<24} overhead: {overhead_str:<11} score: {allscore_str:<11} expected savings: {expected_savings_str:<11} ram used: {format_bytes(get_memory_usage()):<11}",end="\n")

def encode_byte_map_to_256bit(byte_map): #useful to store more than 32 dictionary values in no more than 32bytes

    encoded = bitarray(256)
    encoded.setall(0)  #initialize all bits to 0

    for value in byte_map:

        if 0 <= value <= 255:
            encoded[value] = 1

    byte_array = encoded.tobytes()

    return byte_array

def decode_256bit_from_bytes(encoded_bytes):

    #convert the byte array back to a bitarray
    encoded = bitarray()
    encoded.frombytes(bytearray(encoded_bytes))

    #reconstruct the original list of integers
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

    #count the unique items
    counts = count_unique_items(item_list)

    #filter and sort the items by frequency (only items with frequency > 1)
    filtered_sorted_items = sorted(
        (item for item in counts.items() if item[1] > 1), 
        key=lambda x: x[1], 
        reverse=True
    )

    #convert tuples back to lists
    sorted_lists = [list(item[0]) for item in filtered_sorted_items]

    return sorted_lists

def count_unique_items(item_list):

    unique_counts = {}

    for item in item_list:

        #convert the unhashable item (e.g., list or dict) to a hashable type (e.g., tuple or frozenset)
        hashable_item = tuple(item) if isinstance(item, list) else frozenset(item.items()) if isinstance(item, dict) else item

        if hashable_item in unique_counts:
            unique_counts[hashable_item] += 1
        else:
            unique_counts[hashable_item] = 1

    #return the count of unique items
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

def decompress(file_path):  #the main decompression loop
    with open(file_path + '.raz', 'rb') as f:
        bytestream = f.read()

    byte_values = list(bytestream)
    decompressed = []
    idx = 0

    sequence = bytearray(b'%RAZv') + bytearray([0, 1]) + bytearray(b'x')
    while idx < len(bytestream) - len(sequence) + 1:
        if bytestream[idx:idx + len(sequence)] == sequence:
            break
        if idx > len(sequence):
            print('This isn\'t a valid RAZ file!')
            return
        idx += 1

    idx += len(sequence)
    instructions = []
    byte_maps = []

    while idx < len(bytestream):
        instruction = bytestream[idx]

        if instruction == 10:
            idx += 1
            decompressed.append(bytestream[idx])
            idx += 1

        elif instruction == 0:
            idx += 1
            length = bytestream[idx]
            decompressed.extend(bytestream[idx + 1:idx + 1 + length])
            idx += length + 1

        elif instruction == 41:
            idx += 1
            length = struct.unpack(">H", bytestream[idx:idx + 2])[0]
            decompressed.extend(bytestream[idx + 2:idx + 2 + length])
            idx += length + 2

        elif 1 <= instruction <= 7 or 11 <= instruction <= 17:
            idx, decompressed_data, byte_map = handle_bit_reduced_data(bytestream, idx + 1, instruction)
            decompressed.extend(decompressed_data)
            instructions.append(instruction)
            byte_maps.append(byte_map)

        elif instruction == 9 or instruction == 19:
            idx += 1
            go_back = bytestream[idx]
            referenced_instruction = instructions[(len(instructions) - 1) - go_back]

            if referenced_instruction > 10 and instruction < 10:
                instruction = referenced_instruction - 10

            elif referenced_instruction < 10 and instruction > 10:
                instruction = referenced_instruction + 10

            else:
                instruction = referenced_instruction

            byte_map = byte_maps[(len(byte_maps) - 1) - bytestream[idx]]
            idx += 1

            new_bytestream = []
            new_bytestream.append(bytestream[idx])

            if instruction > 10:
                new_bytestream.append(bytestream[idx + 1])

            byte_map_to_add = []

            for key in byte_map:
                byte_map_to_add.append(key)

            if len(byte_map_to_add) > 32:
                byte_map_to_add = encode_byte_map_to_256bit(byte_map_to_add)

            new_bytestream.extend(byte_map_to_add)

            if instruction > 10:
                length = struct.unpack(">H", bytes(bytestream[idx:idx + 2]))[0]
                bit_length = instruction - 10
                bytestream_limit = ((length * bit_length + 7) // 8) + idx + 2

                for bytez in bytestream[idx + 2:bytestream_limit]:
                    new_bytestream.append(bytez)

            else:
                bytestream_limit = ((bytestream[idx] * instruction + 7) // 8) + idx + 1

                for bytez in bytestream[idx + 1:bytestream_limit]:
                    new_bytestream.append(bytez)

            nidx, decompressed_data, byte_map = handle_bit_reduced_data(new_bytestream, 0, instruction)

            idx += nidx - len(byte_map)

            decompressed.extend(decompressed_data)

        elif instruction == 77:  #handle repeat instruction
            idx += 1
            byte_to_repeat = bytestream[idx]
            idx += 1
            repeat_count = bytestream[idx]
            idx += 1
            decompressed.extend([byte_to_repeat] * repeat_count)

        elif instruction == 78:  #handle repeat instruction
            idx += 1
            byte_to_repeat = bytestream[idx]
            idx += 1
            repeat_count = struct.unpack(">H", bytes(bytestream[idx:idx+2]))[0]
            idx += 2
            decompressed.extend([byte_to_repeat] * repeat_count)

        else:
            print(f'trouble at idx: {idx}\tinstruction: {instruction}')

    if idx < len(bytestream):
        decompressed.extend(bytestream[idx:])

    with open('decompressed_' + file_path, 'wb') as f:
        f.write(bytearray(decompressed))

    print(f'\nsize data:\noriginal size:\t\t{format_bytes(len(decompressed))}\ncompressed size:\t{format_bytes(len(bytestream))}\ncompression ratio:\t{(len(bytestream) / len(decompressed))*100:.3f}%')

def compress_final(final_compressed, file_path):
    #eventually i want to huffman or bitreduce the instructions for better compression ratio. also use the 0bit after an instruction to indicate the length of bytes affected
    #so like (instruction)(affectedbytes)00(3bytelength). 0bits in the right position will make all the important stuff.
    bytestream = bytearray(b'%RAZv') + bytearray([0, 1]) + bytearray(b'x')  #magic number
    past_instructions = []
    past_byte_maps = []

    for lst in final_compressed:  #write the compressed file according to instructions
        instruction = lst[0]
        data = lst[1:]

        if instruction == 10:  #next byte unaffected
            bytestream.append(10)
            bytestream.append(data[0])

        elif instruction == 77:  #repeat next byte x times
            bytestream.append(77)
            bytestream.append(data[0])  #byte to repeat
            bytestream.append(data[1])  #repeat count

        elif instruction == 78:  #repeat next byte x times
            bytestream.append(78)
            bytestream.append(data[0])  #byte to repeat
            bytestream.extend(struct.pack(">H",data[1]))  #repeat count

        elif instruction == 0:  #next x bytes unaffected
            length = len(data)

            if length < 256:
                bytestream.append(0)
                bytestream.append(length)
                bytestream.extend(data)

            elif len(data) < 65536:
                bytestream.append(41)
                bytestream.extend(struct.pack(">H", length))
                bytestream.extend(data)

            else:  #divide into chunks that are smaller than 65536 and bigger than 256 to avoid handling chunks bigger than 64KB
                total_length = len(data)
                chunk_size = 65535

                while total_length / (total_length // chunk_size) <= 255:
                    chunk_size -= 1

                for i in range(0, total_length, chunk_size):
                    chunk = data[i:i + chunk_size]
                    bytestream.extend([41] + list(struct.pack(">H", len(chunk))))
                    bytestream.extend(chunk)

        elif 1 <= instruction <= 7:  #bit reduce this data
            unique_bytes = sorted(list(set(data)))
            original_instruction = instruction
            max_unique_values = min(2 ** instruction, 32)
            go_back = -1

            while len(past_instructions) > 256:
                past_instructions.pop(0)

            for ii in range(len(past_instructions), 0, -1):  #check past instructions and maps to see if we can reduce the instruction to 9
                #this will eventually need to be changed so that it can handle all instructions but only the relevant ones and not calculate randomly that could cause the read of an invalid instruction
                #also the way it's setup now the instruction can only handle 2byte chunk lengths not 2 bytes goback instructions (like go back 10000)

                if (past_instructions[ii - 1] == instruction or past_instructions[ii - 1] == instruction + 10 or past_instructions[ii - 1] == instruction - 10) and past_byte_maps[ii - 1] == unique_bytes:
                    go_back = len(past_instructions) - ii

                    if go_back < 256:  #storing go_back in 1 byte 255 is the max value I will go back (for the moment)
                        instruction = 9
                        break
                    else:
                        go_back = -1  #no need to go back

            if go_back == -1:  #normal bit reduction of bytes
                if len(data) < 256:
                    bytestream.append(instruction)
                    bytestream.append(len(data))

                elif len(data) < 65536:
                    bytestream.append(instruction + 10)
                    bytestream.extend(list(struct.pack(">H", len(data))))

                else:
                    print('omg!')  #omg isn't a very good way to handle this case

                if len(unique_bytes) > 32:  #encode in 256bits byte maps larger than 32
                    unique_bytes_packed = encode_byte_map_to_256bit(unique_bytes)
                    bytestream.extend(unique_bytes_packed)
                    
                elif len(unique_bytes) < max_unique_values:  #double last map value to truncate it before max length
                    unique_bytes.append(unique_bytes[-1])
                    bytestream.extend(unique_bytes)

                else:
                    bytestream.extend(unique_bytes)

                past_instructions.append(instruction)
                past_byte_maps.append(unique_bytes)

            else:  #if instruction is already present
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
                    print('omg!')  #bah

                if original_instruction < 10:  #return the right instruction to encode data
                    instruction = original_instruction

                else:
                    instruction = original_instruction - 10

            byte_map = {}
            for idx, byte in enumerate(unique_bytes):  #build byte map
                byte_map[byte] = idx

            if len(unique_bytes) > 2 and unique_bytes[-1] == unique_bytes[-2]:  #handle truncated byte map
                byte_map[unique_bytes[-2]] = len(unique_bytes) - 2

            packed_data = []

            for byte in data:  #write bit reduced data after mapping
                value_to_write = byte_map[byte]
                packed_data.extend(format(value_to_write, f'0{instruction}b'))

            while len(packed_data) % 8 != 0:  #append 0 bits if value ends before end of byte
                packed_data.append('0')

            for i in range(0, len(packed_data), 8):  #add packed data to the bytestream
                bytestream.append(int("".join(packed_data[i:i + 8]), 2))

    with open(file_path + '.raz', 'wb') as f:
        f.write(bytestream)
        
length_thresholds = {1: 11, 2: 15, 3: 24, 4: 43, 5: 81, 6: 159, 7: 319}
unique_byte_thresholds = {1: 2, 2: 4, 3: 8, 4: 16, 5: 32, 6: 64, 7: 128}    
multipliers = {1: 0.125, 2: 0.25, 3: 0.375, 4: 0.5, 5: 0.625, 6: 0.75, 7: 0.875}

def calculate_scores_chunk(chunk, unique_byte_threshold, length_threshold):
    row_chunk = np.zeros(len(chunk), dtype=int)
    for start_pos in range(len(chunk)):
        unique_bytes = set()
        max_length = 0
        for end_pos in range(start_pos, min(len(chunk), start_pos + 65535)):
            last_checked_byte = chunk[end_pos]
            if isinstance(last_checked_byte, list):
                break
            unique_bytes.add(last_checked_byte)
            if len(unique_bytes) > unique_byte_threshold:
                break
            max_length += 1
        if max_length >= length_threshold:
            row_chunk[start_pos] = max_length
    return row_chunk

def calculate_scores(bytes_list, reduction):
    print(f"\r{reduction}bit redux analysis in progress...", end="")
    len_bytes = len(bytes_list)
    unique_byte_threshold = unique_byte_thresholds[reduction]
    length_threshold = length_thresholds[reduction]

    num_workers = cpu_count()
    chunk_size = len_bytes // num_workers + 1
    chunks = [bytes_list[i:i + chunk_size] for i in range(0, len_bytes, chunk_size)]

    with Pool(num_workers) as pool:
        results = pool.starmap(calculate_scores_chunk, [(chunk, unique_byte_threshold, length_threshold) for chunk in chunks])

    scores = np.concatenate(results)
    print(f"\r{reduction}bit redux analysis done! reducing...              ", end="")
    return scores

def bit_reduction(less_bit_compressed, bits):

    more_bit_scores = calculate_scores(less_bit_compressed, bits)

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
                i += score - 1

        else:
            more_bit_compressed.append(less_bit_compressed[i])

        i += 1

    expected_savings = allscore-overhead-int(allscore*(.125*bits))
    print_analysis_info(str(bits) +'bit redux done!',overhead,allscore,expected_savings)

    return more_bit_compressed


    
def handle_repeats_chunk(chunk):
    compressed = []
    allscore = 0
    overhead = 0
    i = 0
    len_chunk = len(chunk)

    while i < len_chunk:
        if isinstance(chunk[i], list):
            compressed.append(chunk[i])
            i += 1
            continue

        repeat_count = 1

        while i + repeat_count < len_chunk and chunk[i] == chunk[i + repeat_count] and repeat_count < 65535:
            repeat_count += 1

        if repeat_count > 3:  # choose a threshold for when it's beneficial to use the repeat instruction
            if repeat_count < 255:
                compressed.append([77, chunk[i], repeat_count])
                i += repeat_count
                allscore += repeat_count
                overhead += 2  # 1 byte for the byte to repeat and 1 byte for the repeat count
            else:
                compressed.append([78, chunk[i], repeat_count])
                i += repeat_count
                allscore += repeat_count
                overhead += 3  # 1 byte for the byte to repeat and 2 bytes for the repeat count
        else:
            compressed.append(chunk[i])
            i += 1

    return compressed, allscore, overhead

def handle_repeats(data):
    len_data = len(data)

    num_workers = cpu_count()
    chunk_size = len_data // num_workers + 1
    chunks = [data[i:i + chunk_size] for i in range(0, len_data, chunk_size)]

    with Pool(num_workers) as pool:
        results = pool.map(handle_repeats_chunk, chunks)

    compressed = []
    allscore = 0
    overhead = 0

    for result in results:
        chunk_compressed, chunk_allscore, chunk_overhead = result
        compressed.extend(chunk_compressed)
        allscore += chunk_allscore
        overhead += chunk_overhead

    expected_savings = allscore - overhead
    print(f"\rrepeats analysis done! repeating...            ", end="")
    
    print_analysis_info('repeats done!', overhead, allscore, expected_savings)

    return compressed

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

    return marked_data

def algorithm_score_analysis(file_path):
    start_time = time.time()  

    with open(file_path, 'rb') as f:
        original_data = f.read()

    print(f"\ncompressing {file_path} now...         \n")

    data = original_data
    
    #---
    #---
    #pass a list of commands through argument and use them in the order they are given and only those that are given.
    #---
    #---

    data = handle_repeats(data)
    gc.collect() #when trying to compress larger files memory usage can get out of hand so I manually garbage collect to keep memory usage lower. need to improve memory usage and file chunking.

    data = bit_reduction(data, 1)
    gc.collect()

    data = bit_reduction(data, 2)
    gc.collect()

    data = bit_reduction(data, 3)
    gc.collect()

    data = bit_reduction(data, 4)
    gc.collect()

    data = bit_reduction(data, 5)
    gc.collect()

    data = bit_reduction(data, 6)
    gc.collect()

    data = bit_reduction(data, 7)
    gc.collect()

    final_compressed = mark_uncompressed(data)

    end_time = time.time()
    elapsed_time = end_time - start_time
    analysis_time_str = (f"analysis time:\t\t{format_time(elapsed_time)}")

    start_time = time.time()
    compress_final(final_compressed, file_path)
    end_time = time.time()
    elapsed_time = end_time - start_time
    compression_time_str = (f"compression time:\t{format_time(elapsed_time)}")

    start_time = time.time()
    decompress(file_path)
    end_time = time.time()
    elapsed_time = end_time - start_time
    decompression_time_str = (f"decompression time:\t{format_time(elapsed_time)}")
    
    print(f"\ntimes:\n{analysis_time_str}\n{compression_time_str}\n{decompression_time_str}\n\ntest completed successfully!")

def main():
    #check if the file path argument is provided
    if len(sys.argv) != 2:
        print("usage: raz.py <file_path>")
        sys.exit()  #exit the program if file path is not provided

    file_path = sys.argv[1]
    algorithm_score_analysis(file_path)

if __name__ == "__main__":
    main()
