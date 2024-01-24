import crypt
import multiprocessing
import getopt
import sys
from sys import argv
import time

def input():
    shadow_file = None
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "f:")
    except Exception as e:
        print(f"Error: {e.__class__} has occured")
    for opt, arg in opts:
        if opt in ['-f']:
            shadow_file = arg  
    if(shadow_file is None):
        print("Shadow file not specified, defaulting to 'shadow2'")
        shadow_file = 'shadow2'
    options = [shadow_file]
    return options

def encrypt(password, encrypted_password, salt):
    # Calculate the encrypted guess using the same algorithm used by the shadow file
    encrypted_guess = crypt.crypt(password, f'$6${salt}$')

    # If the encrypted guess matches the encrypted password, we've found the right password
    if encrypted_guess == encrypted_password:
        return password

def decrypt(shadow_file, dictionary_file, count, total):
    # Open the shadow file and read its contents into a list
    with open(shadow_file, 'r') as f:
        shadow_entries = f.readlines()

    # Open the dictionary file and read its contents into a list
    with open(dictionary_file, 'r') as f:
        passwords = f.readlines()

    # Strip the newline characters from the passwords
    passwords = [p.strip() for p in passwords]

    # Create a pool of encrypt processes
    pool = multiprocessing.Pool()

    # Iterate over each entry in the shadow file
    for shadow_entry in shadow_entries:
        # Split the entry into its components
        username, encrypted_password, rest = shadow_entry.split(':')

        # Extract the salt from the encrypted password
        salt = encrypted_password.split('$')[2]
        algo = encrypted_password.split('$')[1]
        
        if algo == '1':
            print ("\nHash type: MD5")
        elif algo == '2a':
            print ("\nHash type: Blowfish")
        elif algo == '5':
            print ("\nHash type: SHA-256")
        elif algo == '6':
            print ("\nHash type: SHA-512")
        else:
            print ("\nUnable to determine Hashing Algorithm \n")


        # Use the encrypt pool to try each password in the dictionary in parallel
        start = time.time()
        results = pool.starmap(encrypt, [(password, encrypted_password, salt) for password in passwords])
        count += 1
        end = time.time()
        total_time = end - start
        rounded = round(total_time, 4)
        total = total + rounded
        # Check if any of the results are not None (i.e., a password was found)
        for result in results:
            if result is not None:
                print('Username:', username)
                print('Password:', result)
                print('Number of attempts: ', count)
                print('Time elapsed (in seconds): ', rounded)
                break
        print('\nTotal time elapsed (in seconds): ', round(total, 4))

# Call the function to start the decryption process
options = input()
shadow = options[0]
count = 0
total = 0
decrypt(shadow, 'words.txt', count, total)
