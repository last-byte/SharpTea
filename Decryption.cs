using System;
using System.Collections.Generic;
using System.Text;

namespace SharpTea
{
    class Decryption
    {

        static private byte[] decryptionRoutine(UInt32 vector0, UInt32 vector1, byte[] key)
        {
            // we split the key in 4 chunks
            uint keyChunk3 = BitConverter.ToUInt32(key, 0);
            uint keyChunk2 = BitConverter.ToUInt32(key, 4);
            uint keyChunk1 = BitConverter.ToUInt32(key, 8);
            uint keyChunk0 = BitConverter.ToUInt32(key, 12);

            //define list to which encrypted bytes will be appended
            var decryptedList = new List<byte>();

            uint sum = 0xC6EF3720;
            uint delta = 0x9E3779B9;

            // ----------- TEA Decryption Algorithm ----------- //
            for (int i = 0; i < 32; i++)
            {
                vector1 -= ((vector0 << 4) + keyChunk2) ^ (vector0 + sum) ^ ((vector0 >> 5) + keyChunk3);
                vector0 -= ((vector1 << 4) + keyChunk0) ^ (vector1 + sum) ^ ((vector1 >> 5) + keyChunk1);
                sum -= delta;
            }
            // ----------- TEA Decryption Algorithm ----------- //

            // populate the list with the two vectors
            foreach (var b in BitConverter.GetBytes(vector1))
            {
                decryptedList.Add(b);
            }

            foreach (var b in BitConverter.GetBytes(vector0))
            {
                decryptedList.Add(b);
            }

            // return the byte array
            var returnArray = decryptedList.ToArray();
            Array.Reverse(returnArray);
            return returnArray;
        }

        // decrypt encrypted bytes
        static public byte[] GetDecryptedBytes(byte[] toDecrypt, byte[] key)
        {
            // throw exception if the key is not 16 byte long
            if (key.Length != 16)
            {
                throw new ArgumentException($"Provided key should be 16 byte long. Length is {key.Length}");
            }

            //throw exception if the ciphertext is not divisible by 8
            if ((toDecrypt.Length % 8) != 0)
            {
                throw new ArgumentException($"Provided ciphertext length should be a multiple of 8. Length is {toDecrypt.Length}");
            }

            // we need the key to be big endian so we reverse it
            Array.Reverse(key);

            // setup two lists that will contain the cleartext and ciphertext
            var cleartext = new List<byte>();
            var ciphertext = new List<byte>();

            // fill list with the bytes to decrypt
            foreach (var b in toDecrypt)
            {
                ciphertext.Add(b);
            }

            // create a temporary array from the ciphertext list to iterate on
            var tempArray = ciphertext.ToArray();
            var vector0Array = new byte[4];
            var vector1Array = new byte[4];

            // start decrypting the bytes in tempArray in groups of 8
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

                // call the decryption routine on the chunks
                var decryptedBytes = decryptionRoutine(vector0, vector1, key);

                // parse vector0 and add the bytes to the cleartext list
                foreach (var b in decryptedBytes)
                {
                    cleartext.Add(b);
                }
            }

            // create a byte array from the cleartext byte list and return it
            var decrypted = cleartext.ToArray();
            return decrypted;
        }

        // function overloading (same function name, different parameters)
        // define a wrapper around GetDecryptedBytes which can take also strings

        // decrypt bytes using string key
        static public string GetDecryptedString(byte[] toDecrypt, string key)
        {
            var keyBytes = Encoding.ASCII.GetBytes(key);
            var decryptedBytes = GetDecryptedBytes(toDecrypt, keyBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        // decrypt base64 string using string key
        static public string GetDecryptedString(string toDecrypt, string key)
        {
            var encryptedBytes = Convert.FromBase64String(toDecrypt);
            var keyBytes = Encoding.ASCII.GetBytes(key);
            var decryptedBytes = GetDecryptedBytes(encryptedBytes, keyBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        // decrypt base64 string using byte key
        static public string GetDecryptedStringFromBase64(string toDecrypt, byte[] key)
        {
            var encryptedBytes = Convert.FromBase64String(toDecrypt);
            var keyBytes = key;
            var decryptedBytes = GetDecryptedBytes(encryptedBytes, keyBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        // decrypt base64 string using base64 key
        static public string GetDecryptedStringFromBase64(string toDecrypt, string key)
        {
            var encryptedBytes = Convert.FromBase64String(toDecrypt);
            var keyBytes = Convert.FromBase64String(key);
            var decryptedBytes = GetDecryptedBytes(encryptedBytes, keyBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
