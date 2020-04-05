using System;
using System.Collections.Generic;
using System.Text;

namespace SharpTea
{
    class Encryption
    {
        static private byte[] encryptionRoutine(UInt32 vector0, UInt32 vector1, byte[] key)
        {

            // we split the key in 4 chunks
            uint keyChunk3 = BitConverter.ToUInt32(key, 0);
            uint keyChunk2 = BitConverter.ToUInt32(key, 4);
            uint keyChunk1 = BitConverter.ToUInt32(key, 8);
            uint keyChunk0 = BitConverter.ToUInt32(key, 12);

            //define list to which encrypted bytes will be appended
            var encryptedList = new List<byte>();

            // ----------- TEA Encryption Algorithm ----------- //
            uint sum = 0;
            uint delta = 0x9E3779B9;

            for (int i = 0; i < 32; i++)
            {
                sum += delta;
                vector0 += ((vector1 << 4) + keyChunk0) ^ (vector1 + sum) ^ ((vector1 >> 5) + keyChunk1);
                vector1 += ((vector0 << 4) + keyChunk2) ^ (vector0 + sum) ^ ((vector0 >> 5) + keyChunk3);
            }
            // ----------- TEA Encryption Algorithm ----------- //

            // populate the list with the two vectors
            foreach (var b in BitConverter.GetBytes(vector1))
            {
                encryptedList.Add(b);
            }

            foreach (var b in BitConverter.GetBytes(vector0))
            {
                encryptedList.Add(b);
            }

            // return the byte array
            var returnArray = encryptedList.ToArray();
            Array.Reverse(returnArray);
            return returnArray;

        }

        static public byte[] GetEncryptedBytes(byte[] toEncrypt, byte[] key, byte padding = 0x90)
        {
            // throw exception if the key is not 16 byte long
            if (key.Length != 16)
            {
                throw new ArgumentException($"Provided key should be 16 byte long. Length is {key.Length}");
            }

            // we need the key to be big endian so we reverse it
            Array.Reverse(key);

            // setup two lists that will contain the cleartext and ciphertext
            var cleartext = new List<byte>();
            var cyphertext = new List<byte>();

            // fill list with the bytes to encrypt
            foreach (var b in toEncrypt)
            {
                cleartext.Add(b);
            }

            // check if the list is divisible by 8, pad it if not
            if ((cleartext.Count % 8) != 0)
            {
                var missingElements = 8 - cleartext.Count % 8;
                for (int i = 0; i < missingElements; i++)
                {
                    // since the idea is to encrypt a shellcode
                    // the NOP opcode is used to pad the cleartext
                    cleartext.Add(padding);
                }
            }

            // create a temporary array from the cleartext list to iterate on
            var tempArray = cleartext.ToArray();
            var vector0Array = new byte[4];
            var vector1Array = new byte[4];

            // start encrypting the bytes in tempArray in groups of 8
            for (int i = 0; i < tempArray.Length; i += 8)
            {
                // we need vector0 and vector1 to be copied as big endian
                // so we instantiate two new arrays and reverse them
                Array.Copy(tempArray, i, vector0Array, 0, 4);
                Array.Copy(tempArray, i + 4, vector1Array, 0, 4);
                Array.Reverse(vector0Array);
                Array.Reverse(vector1Array);

                // convert the two arrays to Int32
                uint vector0 = BitConverter.ToUInt32(vector0Array, 0);
                uint vector1 = BitConverter.ToUInt32(vector1Array, 0);

                // call the encryption routine on the chunks
                var encryptedBytes = encryptionRoutine(vector0, vector1, key);

                // parse vector0 and add the bytes to the ciphertext list
                foreach (var b in encryptedBytes)
                {
                    cyphertext.Add(b);
                }
            }

            // create a byte array from the ciphertext byte list and return it
            var encrypted = cyphertext.ToArray();
            return encrypted;
        }

        // function overloading (same function name, different parameters)
        // define a wrapper around GetEncryptedBytes which can take also strings
        static public byte[] GetEncryptedBytes(string toEncrypt, string key, byte padding = 0x90)
        {
            var toEncryptBytes = Encoding.ASCII.GetBytes(toEncrypt);
            var keyBytes = Encoding.ASCII.GetBytes(key);

            return GetEncryptedBytes(toEncryptBytes, keyBytes, padding);
        }

        static public string GetEncryptedString(string toEncrypt, string key, byte padding = 0x90)
        {
            var toEncryptBytes = Encoding.ASCII.GetBytes(toEncrypt);
            var keyBytes = Encoding.ASCII.GetBytes(key);
            var encryptedBytes = GetEncryptedBytes(toEncryptBytes, keyBytes, padding);
            var encryptedString = Convert.ToBase64String(encryptedBytes, 0, encryptedBytes.Length);

            return encryptedString;
        }
    }
}
