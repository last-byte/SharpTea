using System;
using System.Text;

namespace SharpTea
{
    class Program
    {
        static void Main(string[] args)
        {
            // key and cleartext can either be a string, a byte array or a base64 string
            // function overloading takes care of conversion :)
            var key = "VoidsexIsTheBest";
            var cleartext = "0123456789ABCDEF";

            Console.WriteLine($"Cleartext is: {cleartext}");
            Console.WriteLine($"Key is: {key}");


            // return a base64 encrypted string
            var encrypted = Encryption.GetEncryptedString(cleartext, key);
            
            // decrypt base64 encoded string
            var decrypted = Decryption.GetDecryptedString(encrypted, key);

            Console.WriteLine($"The encrypted string is {encrypted}");
            Console.WriteLine($"The decrypted string is {decrypted}");
        }
    }
}
